package api

import (
	"io/fs"
	"net/http"
	"strings"
	"time"

	"iptables-web/internal/store"
)

func NewRouter(h *Handler, authH *AuthHandler, userH *UserHandler, userStore *store.UserStore, webFS fs.FS) http.Handler {
	mux := http.NewServeMux()
	authCfg := newAuthConfig(userStore)

	// Strip the "web" directory prefix from embedded filesystem
	webFS, _ = fs.Sub(webFS, "web")

	var handler http.Handler = mux
	handler = recoveryMiddleware(handler)
	handler = rateLimitMiddleware(600, time.Minute)(handler)
	handler = loggingMiddleware(handler)
	handler = requestIDMiddleware(handler)
	handler = authMiddleware(authCfg)(handler)

	// Auth routes
	mux.HandleFunc("/api/v1/auth/captcha", authH.GetCaptcha)
	mux.HandleFunc("/api/v1/auth/login", authH.Login)
	mux.HandleFunc("/api/v1/auth/logout", authH.Logout)
	mux.HandleFunc("/api/v1/auth/session", authH.SessionCheck)

	// Self-service password change (any authenticated user)
	mux.HandleFunc("/api/v1/auth/password", userH.ChangePassword)

	// User management — all authenticated users can view, admin for mutations
	adminOnly := adminRequired()
	usersHandler := func(w http.ResponseWriter, r *http.Request) {
		id, action := extractUserPath(r.URL.Path)
		// GET /api/v1/users (list) or /api/v1/users/{id} (single) — any authenticated user
		if r.Method == http.MethodGet {
			if id == "" {
				userH.ListUsers(w, r)
				return
			}
			userH.GetUser(w, r)
			return
		}
		// POST /api/v1/users — admin only
		if id == "" && action == "" && r.Method == http.MethodPost {
			adminOnly(http.HandlerFunc(userH.CreateUser)).ServeHTTP(w, r)
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

	// API routes
	mux.HandleFunc("/api/v1/health", h.HealthCheck)
	mux.HandleFunc("/api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.ListRules(w, r)
		case http.MethodPost:
			adminOnly(http.HandlerFunc(h.CreateRule)).ServeHTTP(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
		}
	})
	mux.HandleFunc("/api/v1/rules/reorder", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use PUT")
			return
		}
		adminOnly(http.HandlerFunc(h.ReorderRules)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/rules/", func(w http.ResponseWriter, r *http.Request) {
		id, action := extractRulePath(r.URL.Path)
		if id == "" {
			respondError(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		switch {
		case action == "/toggle" && r.Method == http.MethodPost:
			adminOnly(http.HandlerFunc(h.ToggleRule)).ServeHTTP(w, r)
		case action == "" && r.Method == http.MethodGet:
			h.GetRule(w, r)
		case action == "" && r.Method == http.MethodPut:
			adminOnly(http.HandlerFunc(h.UpdateRule)).ServeHTTP(w, r)
		case action == "" && r.Method == http.MethodDelete:
			adminOnly(http.HandlerFunc(h.DeleteRule)).ServeHTTP(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid method")
		}
	})
	mux.HandleFunc("/api/v1/system/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		h.GetSystemInfo(w, r)
	})
	mux.HandleFunc("/api/v1/system/chains", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		h.GetChains(w, r)
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
		h.GetChainRules(w, r)
	})
	mux.HandleFunc("/api/v1/system/backup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		adminOnly(http.HandlerFunc(h.BackupRules)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/system/restore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		adminOnly(http.HandlerFunc(h.RestoreRules)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/v1/system/managed-rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use DELETE")
			return
		}
		adminOnly(http.HandlerFunc(h.ClearManagedRules)).ServeHTTP(w, r)
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
		h.GetDockerMappings(w, r)
	})
	mux.HandleFunc("/api/v1/docker/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		h.GetDockerDiagnostics(w, r)
	})
	mux.HandleFunc("/api/v1/docker/whitelist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		adminOnly(http.HandlerFunc(h.CreateDockerWhitelist)).ServeHTTP(w, r)
	})

	// Serve embedded frontend
	fileServer := http.FileServer(http.FS(webFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			loginData, err := fs.ReadFile(webFS, "login.html")
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(loginData)
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
