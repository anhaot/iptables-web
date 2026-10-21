package api

import (
	"io/fs"
	"net/http"
	"strings"
	"time"

	"iptables-web/internal/store"
)

func NewRouter(h *Handler, authH *AuthHandler, userH *UserHandler, hostH *HostHandler, enrollmentH *EnrollmentHandler, accessKeyH *AccessKeyHandler, userStore *store.UserStore, apiKeyStore *store.APIKeyStore, webFS fs.FS) http.Handler {
	mux := http.NewServeMux()
	authCfg := newAuthConfig(userStore, apiKeyStore)

	// Strip the "web" directory prefix from embedded filesystem
	webFS, _ = fs.Sub(webFS, "web")

	var handler http.Handler = mux
	handler = controllerMiddleware(handler, h, userStore, hostH.store, apiKeyStore, authCfg)

	// Auth routes
	mux.HandleFunc("/api/v1/auth/captcha", authH.GetCaptcha)
	mux.HandleFunc("/api/v1/auth/policy", authH.GetPolicy)
	mux.HandleFunc("/api/v1/auth/login", authH.Login)
	mux.HandleFunc("/api/v1/auth/logout", authH.Logout)
	mux.HandleFunc("/api/v1/auth/session", authH.SessionCheck)

	// Self-service password change (any authenticated user)
	mux.HandleFunc("/api/v1/auth/password", userH.ChangePassword)

	// User inventory and host-assignment policy are controller-admin only.
	adminOnly := adminRequired()
	localOnly := localHostRequired()
	usersHandler := func(w http.ResponseWriter, r *http.Request) {
		id, action := extractUserPath(r.URL.Path)
		// GET /api/v1/users (list) or /api/v1/users/{id} (single) — admin only
		if r.Method == http.MethodGet {
			adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if id == "" {
					userH.ListUsers(w, r)
					return
				}
				userH.GetUser(w, r)
			})).ServeHTTP(w, r)
			return
		}
		// POST /api/v1/users — admin only
		if id == "" && action == "" && r.Method == http.MethodPost {
			adminOnly(http.HandlerFunc(userH.CreateUser)).ServeHTTP(w, r)
			return
		}
		if id != "" && action == "/reset-account" && r.Method == http.MethodPost {
			adminOnly(http.HandlerFunc(userH.ResetAccount)).ServeHTTP(w, r)
			return
		}
		if id != "" && action == "/unlock" && r.Method == http.MethodPost {
			adminOnly(http.HandlerFunc(userH.UnlockAccount)).ServeHTTP(w, r)
			return
		}
		// PUT/DELETE /api/v1/users/{id} — admin only
		if id != "" && (r.Method == http.MethodPut || r.Method == http.MethodDelete) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodPut:
					userH.UpdateUser(w, r)
				case http.MethodDelete:
					userH.DeleteUser(w, r)
				}
			})
			adminOnly(h).ServeHTTP(w, r)
			return
		}
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid method")
	}
	mux.HandleFunc("/api/v1/users", usersHandler)
	mux.HandleFunc("/api/v1/users/", usersHandler)
	mux.Handle("/api/v1/security-policy", adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			userH.GetSecurityPolicy(w, r)
		case http.MethodPut:
			userH.UpdateSecurityPolicy(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or PUT")
		}
	})))

	mux.HandleFunc("/api/v1/monitoring-policy", func(w http.ResponseWriter, r *http.Request) { hostH.monitoringPolicy(w, r, h.changes) })

	// Remote host inventory and explicitly allow-listed API forwarding.
	mux.Handle("/api/v1/hosts", hostH)
	mux.Handle("/api/v1/hosts/", hostH)

	// Agents may only POST a signed request to /register without a browser
	// session. Listing, approval and rejection remain controller-admin routes.
	mux.Handle("/api/v1/agent-enrollments", adminOnly(enrollmentH))
	mux.Handle("/api/v1/agent-enrollments/approve", adminOnly(enrollmentH))
	mux.Handle("/api/v1/agent-enrollments/reject", adminOnly(enrollmentH))
	mux.Handle("/api/v1/agent-enrollments/register", enrollmentH)

	// API credentials for controller-to-agent authentication. Mutations take
	// effect immediately; the plaintext credential is only returned on create.
	mux.Handle("/api/v1/access-keys", accessKeyH)
	mux.Handle("/api/v1/access-keys/", accessKeyH)

	// API routes
	mux.HandleFunc("/api/v1/health", h.HealthCheck)
	mux.HandleFunc("/api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			localOnly(http.HandlerFunc(h.ListRules)).ServeHTTP(w, r)
		case http.MethodPost:
			localOnly(http.HandlerFunc(h.CreateRule)).ServeHTTP(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
		}
	})
	mux.Handle("/api/v1/rules/batch-delete", localOnly(http.HandlerFunc(postOnly(h.BatchDeleteRules))))
	mux.Handle("/api/v1/docker/whitelist/batch", localOnly(http.HandlerFunc(postOnly(h.CreateDockerWhitelistBatch))))
	mux.HandleFunc("/api/v1/rules/reorder", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use PUT")
			return
		}
		localOnly(http.HandlerFunc(h.ReorderRules)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/rules/", func(w http.ResponseWriter, r *http.Request) {
		id, action := extractRulePath(r.URL.Path)
		if id == "" {
			respondError(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		switch {
		case action == "/toggle" && r.Method == http.MethodPost:
			localOnly(http.HandlerFunc(h.ToggleRule)).ServeHTTP(w, r)
		case action == "" && r.Method == http.MethodGet:
			localOnly(http.HandlerFunc(h.GetRule)).ServeHTTP(w, r)
		case action == "" && r.Method == http.MethodPut:
			localOnly(http.HandlerFunc(h.UpdateRule)).ServeHTTP(w, r)
		case action == "" && r.Method == http.MethodDelete:
			localOnly(http.HandlerFunc(h.DeleteRule)).ServeHTTP(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid method")
		}
	})
	mux.HandleFunc("/api/v1/system/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		localOnly(http.HandlerFunc(h.GetSystemInfo)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/system/chains", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		localOnly(http.HandlerFunc(h.GetChains)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/system/chains/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		chain := extractChainPath(r.URL.Path)
		if chain == "" {
			respondError(w, http.StatusNotFound, "not_found", "chain not found")
			return
		}
		localOnly(http.HandlerFunc(h.GetChainRules)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/system/backup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		localOnly(http.HandlerFunc(h.BackupRules)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/system/restore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		localOnly(http.HandlerFunc(h.RestoreRules)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/system/managed-rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use DELETE")
			return
		}
		localOnly(http.HandlerFunc(h.ClearManagedRules)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/system/audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		// The controller audit contains user, host and credential management
		// events, so local-firewall access alone must not expose it.
		adminOnly(http.HandlerFunc(h.GetAuditEvents)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/system/rollback", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			localOnly(http.HandlerFunc(h.GetRollbackStatus)).ServeHTTP(w, r)
		case http.MethodPost:
			localOnly(http.HandlerFunc(h.RollbackLastChange)).ServeHTTP(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
		}
	})
	// Rule assistant
	mux.HandleFunc("/api/v1/assistant/scenarios", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		h.ListScenarios(w, r)
	})
	mux.HandleFunc("/api/v1/assistant/generate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		h.GenerateCommand(w, r)
	})
	mux.HandleFunc("/api/v1/assistant/interpret", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		h.InterpretCommand(w, r)
	})
	mux.HandleFunc("/api/v1/docker/mappings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		localOnly(http.HandlerFunc(h.GetDockerMappings)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/docker/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		localOnly(http.HandlerFunc(h.GetDockerDiagnostics)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/docker/whitelist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		localOnly(http.HandlerFunc(h.CreateDockerWhitelist)).ServeHTTP(w, r)
	})

	// Serve embedded frontend
	fileServer := http.FileServer(http.FS(webFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			landingData, err := fs.ReadFile(webFS, frontendLandingPage(authCfg.enabled))
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(landingData)
			return
		}
		if path == "/index.html" {
			indexData, err := fs.ReadFile(webFS, "index.html")
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexData)
			return
		}
		if path == "/favicon.ico" {
			http.Redirect(w, r, "/favicon.svg", http.StatusTemporaryRedirect)
			return
		}
		fsPath := path[1:]
		if _, err := fs.Stat(webFS, fsPath); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		indexData, err := fs.ReadFile(webFS, "index.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexData)
	})

	return handler
}

func controllerMiddleware(handler http.Handler, h *Handler, userStore *store.UserStore, hostStore *store.HostStore, apiKeyStore *store.APIKeyStore, authCfg *authConfig) http.Handler {
	handler = changeAuditMiddleware(h, userStore, hostStore, apiKeyStore)(handler)
	handler = authMiddleware(authCfg)(handler)
	handler = rateLimitMiddleware(600, time.Minute)(handler)
	handler = recoveryMiddleware(handler)
	handler = loggingMiddleware(handler)
	handler = requestIDMiddleware(handler)
	return handler
}

func frontendLandingPage(authEnabled bool) string {
	if authEnabled {
		return "login.html"
	}
	return "index.html"
}

func extractRulePath(path string) (id string, action string) {
	rest := path[len("/api/v1/rules/"):]
	parts := splitPath(rest)
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], "/" + parts[1]
}

func extractChainPath(path string) string {
	rest := path[len("/api/v1/system/chains/"):]
	parts := splitPath(rest)
	if len(parts) >= 2 && parts[1] == "rules" {
		return parts[0]
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return ""
}

func extractUserPath(path string) (id string, action string) {
	prefix := "/api/v1/users/"
	if !strings.HasPrefix(path, prefix) {
		return "", ""
	}
	rest := path[len(prefix):]
	if rest == "" {
		return "", ""
	}
	parts := splitPath(rest)
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], "/" + parts[1]
}

func splitPath(s string) []string {
	var parts []string
	for _, p := range strings.Split(s, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}
