package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"iptables-web/assets"
	"iptables-web/internal/api"
	"iptables-web/internal/change"
	"iptables-web/internal/iptables"
	appLog "iptables-web/internal/logging"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

var version = "dev"

type Config struct {
	ListenAddr   string
	RulesFile    string
	UsersFile    string
	HostsFile    string
	APIKeysFile  string
	AuditFile    string
	RollbackFile string
	LogLevel     string
}

func LoadConfig() *Config {
	cfg := &Config{
		ListenAddr:   "0.0.0.0:33801",
		RulesFile:    "/data/rules.json",
		UsersFile:    "/data/users.json",
		HostsFile:    "/data/hosts.json",
		APIKeysFile:  "/data/api-keys.json",
		AuditFile:    "/data/audit.jsonl",
		RollbackFile: "/data/rollback.json",
		LogLevel:     "info",
	}
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("RULES_FILE"); v != "" {
		cfg.RulesFile = v
		if cfg.UsersFile == "/data/users.json" {
			cfg.UsersFile = filepath.Join(filepath.Dir(v), "users.json")
		}
		if cfg.HostsFile == "/data/hosts.json" {
			cfg.HostsFile = filepath.Join(filepath.Dir(v), "hosts.json")
		}
		if cfg.APIKeysFile == "/data/api-keys.json" {
			cfg.APIKeysFile = filepath.Join(filepath.Dir(v), "api-keys.json")
		}
		if cfg.AuditFile == "/data/audit.jsonl" {
			cfg.AuditFile = filepath.Join(filepath.Dir(v), "audit.jsonl")
		}
		if cfg.RollbackFile == "/data/rollback.json" {
			cfg.RollbackFile = filepath.Join(filepath.Dir(v), "rollback.json")
		}
	}
	if v := os.Getenv("USERS_FILE"); v != "" {
		cfg.UsersFile = v
	}
	if v := os.Getenv("HOSTS_FILE"); v != "" {
		cfg.HostsFile = v
	}
	if v := os.Getenv("API_KEYS_FILE"); v != "" {
		cfg.APIKeysFile = v
	}
	if v := os.Getenv("AUDIT_FILE"); v != "" {
		cfg.AuditFile = v
	}
	if v := os.Getenv("ROLLBACK_FILE"); v != "" {
		cfg.RollbackFile = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	return cfg
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	cleanup := flag.Bool("cleanup", false, "remove all managed firewall rules, clear the rule store, and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("iptables-web %s\n", version)
		return
	}

	cfg := LoadConfig()
	appLog.SetLevel(cfg.LogLevel)
	if *cleanup {
		if err := cleanupManagedRules(cfg); err != nil {
			log.Fatalf("Failed to clean managed firewall rules: %v", err)
		}
		return
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	appLog.Infof("Starting iptables-web server on %s", cfg.ListenAddr)

	// Initialize rule store
	ruleStore := store.NewJSONStore(cfg.RulesFile)
	if err := ruleStore.Load(); err != nil {
		log.Fatalf("Failed to load rules from %s: %v", cfg.RulesFile, err)
	}
	appLog.Infof("Loaded rules from %s", cfg.RulesFile)

	// Initialize user store
	userStore := store.NewUserStore(cfg.UsersFile)
	if err := userStore.Load(); err != nil {
		log.Fatalf("Failed to load users from %s: %v", cfg.UsersFile, err)
	}
	appLog.Infof("Loaded users from %s", cfg.UsersFile)

	// Initialize the encrypted remote-host inventory. Without an explicit
	// credential key, the store creates and reuses hosts.key automatically.
	hostStore := store.NewHostStore(cfg.HostsFile, os.Getenv("HOST_CREDENTIAL_KEY"))
	if err := hostStore.Load(); err != nil {
		log.Fatalf("Failed to load remote hosts from %s: %v", cfg.HostsFile, err)
	}
	appLog.Infof("Loaded remote hosts from %s", cfg.HostsFile)

	// Dynamically managed target access keys. The file stores only one-way
	// digests, so adding or revoking a key does not require a process restart.
	apiKeyStore := store.NewAPIKeyStore(cfg.APIKeysFile)
	if err := apiKeyStore.Load(); err != nil {
		log.Fatalf("Failed to load API keys from %s: %v", cfg.APIKeysFile, err)
	}
	appLog.Infof("Loaded API access keys from %s", cfg.APIKeysFile)

	// Session and captcha cleanup ticker
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			userStore.CleanupExpiredSessions()
			userStore.CleanupExpiredCaptchas()
		}
	}()

	// Initialize firewall backend (auto-detects iptables/nftables/dev)
	exe, err := iptables.NewExecutor()
	if err != nil {
		log.Fatalf("Failed to initialize firewall backend: %v", err)
	}
	appLog.Infof("Firewall backend initialized: %s", exe.BackendName())
	if removed, err := removeLegacyFirewalldRules(ruleStore, cfg.RulesFile); err != nil {
		log.Fatalf("Failed to remove legacy firewalld records: %v", err)
	} else if removed > 0 {
		appLog.Infof("Removed %d legacy firewalld records from the app store; existing host firewalld configuration was not modified", removed)
	}
	if migrated, err := migrateLegacyDockerDPortRules(ruleStore, exe); err != nil {
		log.Fatalf("Failed to migrate legacy Docker port rules: %v", err)
	} else if migrated > 0 {
		appLog.Infof("Migrated %d Docker rules: removed post-DNAT dport and kept original_dport", migrated)
	}

	// Re-apply persisted rules on startup. SyncRules is idempotent at the app
	// level because every known rule is deleted first, then enabled rules are
	// re-added with compact effective positions.
	allRules, _ := ruleStore.All()
	if err := exe.MigrateLegacyRules(allRules); err != nil {
		log.Fatalf("Failed to migrate legacy unowned firewall rules: %v", err)
	}
	enabled := 0
	for _, rule := range allRules {
		if rule.Enabled {
			enabled++
		}
	}
	if err := exe.SyncRules(allRules); err != nil {
		log.Fatalf("Failed to re-apply persisted rules; refusing to start with inconsistent firewall state: %v", err)
	}
	if err := exe.VerifyRules(allRules); err != nil {
		log.Fatalf("Persisted rules could not be verified; refusing to start: %v", err)
	}
	appLog.Infof("Startup recovery: %d enabled rules synced (%d total in store)",
		enabled, len(allRules))

	// Create handler and router
	apiHandler := api.NewHandler(ruleStore, exe)
	apiHandler.SetChangeManager(change.NewManager(cfg.AuditFile, cfg.RollbackFile, 10*time.Minute))
	authHandler := api.NewAuthHandler(userStore)
	userHandler := api.NewUserHandler(userStore, hostStore)
	hostHandler := api.NewHostHandler(hostStore, userStore)
	enrollmentHandler := api.NewEnrollmentHandler(hostStore)
	accessKeyHandler := api.NewAccessKeyHandler(apiKeyStore)
	router := api.NewRouter(apiHandler, authHandler, userHandler, hostHandler, enrollmentHandler, accessKeyHandler, userStore, apiKeyStore, assets.WebFS)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		appLog.Infof("Received signal %v, shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			appLog.Errorf("Shutdown error: %v", err)
		}
	}()

	appLog.Infof("Server listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	appLog.Infof("Server stopped")
}

func removeLegacyFirewalldRules(ruleStore store.Store, rulesFile string) (int, error) {
	rules, err := ruleStore.All()
	if err != nil {
		return 0, err
	}
	filtered := make([]*model.Rule, 0, len(rules))
	removed := 0
	for _, rule := range rules {
		if strings.EqualFold(strings.TrimSpace(rule.Backend), "firewalld") {
			removed++
			continue
		}
		filtered = append(filtered, rule)
	}
	if removed == 0 {
		return 0, nil
	}
	backupPath := rulesFile + ".pre-iptables-only.bak"
	if _, err := os.Stat(backupPath); errors.Is(err, os.ErrNotExist) {
		if data, readErr := os.ReadFile(rulesFile); readErr == nil {
			if writeErr := os.WriteFile(backupPath, data, 0600); writeErr != nil {
				return 0, fmt.Errorf("backup legacy rules: %w", writeErr)
			}
		}
	}
	if err := ruleStore.ReplaceAll(filtered); err != nil {
		return 0, err
	}
	if err := ruleStore.Save(); err != nil {
		return 0, err
	}
	return removed, nil
}

// migrateLegacyDockerDPortRules repairs rules created with both dport=hostPort
// and original_dport=hostPort. DOCKER-USER sees the post-DNAT container dport,
// so that combination prevents ACCEPT from matching. Only exact managed legacy
// rules are deleted; no chain is flushed.
func migrateLegacyDockerDPortRules(ruleStore store.Store, exe *iptables.Executor) (int, error) {
	rules, err := ruleStore.All()
	if err != nil {
		return 0, err
	}
	original := cloneRuleSet(rules)
	updated := cloneRuleSet(rules)
	legacy := make([]*model.Rule, 0)
	migrated := 0
	for i, rule := range updated {
		if rule == nil || rule.OriginalDPort == "" || rule.DPort == "" {
			continue
		}
		legacy = append(legacy, original[i])
		rule.DPort = ""
		migrated++
	}
	if migrated == 0 {
		return 0, nil
	}
	if err := exe.DeleteRules(legacy); err != nil {
		return 0, fmt.Errorf("delete exact legacy Docker rules: %w", err)
	}
	if err := ruleStore.ReplaceAll(updated); err != nil {
		_ = exe.SyncRules(original)
		return 0, err
	}
	if err := ruleStore.Save(); err != nil {
		_ = ruleStore.ReplaceAll(original)
		_ = ruleStore.Save()
		_ = exe.SyncRules(original)
		return 0, err
	}
	return migrated, nil
}

func cloneRuleSet(rules []*model.Rule) []*model.Rule {
	cloned := make([]*model.Rule, len(rules))
	for i, rule := range rules {
		if rule == nil {
			continue
		}
		cp := *rule
		cloned[i] = &cp
	}
	return cloned
}

func cleanupManagedRules(cfg *Config) error {
	ruleStore := store.NewJSONStore(cfg.RulesFile)
	if err := ruleStore.Load(); err != nil {
		return fmt.Errorf("load rules from %s: %w", cfg.RulesFile, err)
	}
	rules, err := ruleStore.All()
	if err != nil {
		return fmt.Errorf("list managed rules: %w", err)
	}
	if len(rules) == 0 {
		appLog.Infof("Cleanup: no managed rules found in %s", cfg.RulesFile)
		return nil
	}
	exe, err := iptables.NewExecutor()
	if err != nil {
		return fmt.Errorf("initialize firewall backend: %w", err)
	}
	if err := exe.DeleteRules(rules); err != nil {
		return err
	}
	if err := ruleStore.ReplaceAll(nil); err != nil {
		return fmt.Errorf("clear rule store: %w", err)
	}
	if err := ruleStore.Save(); err != nil {
		return fmt.Errorf("persist cleared rule store: %w", err)
	}
	appLog.Infof("Cleanup: removed %d managed rules and cleared %s", len(rules), cfg.RulesFile)
	return nil
}
