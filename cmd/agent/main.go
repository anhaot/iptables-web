package main

import (
	"context"
	"encoding/hex"
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

	"iptables-web/internal/api"
	"iptables-web/internal/change"
	"iptables-web/internal/iptables"
	appLog "iptables-web/internal/logging"
	"iptables-web/internal/store"
)

var version = "dev"

type config struct {
	ListenAddr    string
	RulesFile     string
	AuditFile     string
	RollbackFile  string
	KeyHashFile   string
	IdentityFile  string
	ManagerURL    string
	ManagerCAFile string
	PublicURL     string
	AgentName     string
	AgentGroup    string
	LogLevel      string
}

func loadConfig() config {
	cfg := config{
		ListenAddr:   "0.0.0.0:33802",
		RulesFile:    "/var/lib/iptables-web-agent/rules.json",
		AuditFile:    "/var/lib/iptables-web-agent/audit.jsonl",
		RollbackFile: "/var/lib/iptables-web-agent/rollback.json",
		KeyHashFile:  "/etc/iptables-web-agent/agent.key.sha256",
		IdentityFile: "/etc/iptables-web-agent/agent.identity",
		LogLevel:     "info",
	}
	if hostname, err := os.Hostname(); err == nil {
		cfg.AgentName = hostname
	}
	if value := strings.TrimSpace(os.Getenv("AGENT_LISTEN_ADDR")); value != "" {
		cfg.ListenAddr = value
	}
	if value := strings.TrimSpace(os.Getenv("RULES_FILE")); value != "" {
		cfg.RulesFile = value
		base := filepath.Dir(value)
		cfg.AuditFile = filepath.Join(base, "audit.jsonl")
		cfg.RollbackFile = filepath.Join(base, "rollback.json")
	}
	if value := strings.TrimSpace(os.Getenv("AUDIT_FILE")); value != "" {
		cfg.AuditFile = value
	}
	if value := strings.TrimSpace(os.Getenv("ROLLBACK_FILE")); value != "" {
		cfg.RollbackFile = value
	}
	if value := strings.TrimSpace(os.Getenv("AGENT_KEY_HASH_FILE")); value != "" {
		cfg.KeyHashFile = value
	}
	if value := strings.TrimSpace(os.Getenv("AGENT_IDENTITY_FILE")); value != "" {
		cfg.IdentityFile = value
	}
	if value := strings.TrimSpace(os.Getenv("MANAGER_URL")); value != "" {
		cfg.ManagerURL = value
	}
	if value := strings.TrimSpace(os.Getenv("MANAGER_CA_FILE")); value != "" {
		cfg.ManagerCAFile = value
	}
	if value := strings.TrimSpace(os.Getenv("AGENT_PUBLIC_URL")); value != "" {
		cfg.PublicURL = value
	}
	if value := strings.TrimSpace(os.Getenv("AGENT_NAME")); value != "" {
		cfg.AgentName = value
	}
	if value := strings.TrimSpace(os.Getenv("AGENT_GROUP")); value != "" {
		cfg.AgentGroup = value
	}
	if value := strings.TrimSpace(os.Getenv("LOG_LEVEL")); value != "" {
		cfg.LogLevel = value
	}
	return cfg
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	cleanup := flag.Bool("cleanup", false, "remove all agent-managed firewall rules and clear the rule store")
	flag.Parse()
	if *showVersion {
		fmt.Printf("iptables-web-agent %s\n", version)
		return
	}
	cfg := loadConfig()
	appLog.SetLevel(cfg.LogLevel)
	if *cleanup {
		if err := cleanupRules(cfg); err != nil {
			log.Fatal(err)
		}
		return
	}

	keyHash, initialAgentKey, identity, err := prepareAgentEnrollment(cfg)
	if err != nil {
		log.Fatalf("agent authentication is not configured: %v", err)
	}
	ruleStore := store.NewJSONStore(cfg.RulesFile)
	if err := ruleStore.Load(); err != nil {
		log.Fatalf("load rules: %v", err)
	}
	executor, err := iptables.NewExecutor()
	if err != nil {
		log.Fatalf("initialize firewall backend: %v", err)
	}
	rules, err := ruleStore.All()
	if err != nil {
		log.Fatalf("list managed rules: %v", err)
	}
	if err := executor.SyncRules(rules); err != nil {
		log.Fatalf("restore managed rules: %v", err)
	}
	if err := executor.VerifyRules(rules); err != nil {
		log.Fatalf("verify managed rules: %v", err)
	}

	handler := api.NewHandler(ruleStore, executor)
	handler.SetChangeManager(change.NewManager(cfg.AuditFile, cfg.RollbackFile, 10*time.Minute))
	verifier := api.NewAgentKeyVerifier(keyHash)
	router := api.NewAgentRouterWithVerifier(handler, verifier)
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	if cfg.ManagerURL != "" {
		go runEnrollmentLoop(rootCtx, cfg, identity, initialAgentKey, verifier)
	}
	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		<-signals
		cancelRoot()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	appLog.Infof("iptables-web-agent listening on %s with backend %s", cfg.ListenAddr, executor.BackendName())
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("agent server: %v", err)
	}
}

func loadAgentKeyHash(path string) ([]byte, error) {
	encoded := strings.TrimSpace(os.Getenv("AGENT_KEY_SHA256"))
	if encoded == "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		encoded = strings.TrimSpace(string(data))
	}
	hash, err := hex.DecodeString(encoded)
	if err != nil || len(hash) != 32 {
		return nil, fmt.Errorf("agent key hash must be exactly 64 hexadecimal characters")
	}
	return hash, nil
}

func cleanupRules(cfg config) error {
	ruleStore := store.NewJSONStore(cfg.RulesFile)
	if err := ruleStore.Load(); err != nil {
		return err
	}
	rules, err := ruleStore.All()
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return nil
	}
	executor, err := iptables.NewExecutor()
	if err != nil {
		return err
	}
	if err := executor.DeleteOwnedRules(rules); err != nil {
		return err
	}
	if err := ruleStore.ReplaceAll(nil); err != nil {
		return err
	}
	return ruleStore.Save()
}
