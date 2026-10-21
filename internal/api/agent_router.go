package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"iptables-web/internal/fleet"
)

type AgentKeyVerifier struct {
	mu   sync.RWMutex
	hash []byte
}

func NewAgentKeyVerifier(keyHash []byte) *AgentKeyVerifier {
	verifier := &AgentKeyVerifier{}
	verifier.Update(keyHash)
	return verifier
}

func (v *AgentKeyVerifier) Update(keyHash []byte) {
	v.mu.Lock()
	v.hash = append(v.hash[:0], keyHash...)
	v.mu.Unlock()
}

func (v *AgentKeyVerifier) Valid(key string) bool {
	provided := sha256.Sum256([]byte(key))
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.hash) == sha256.Size && subtle.ConstantTimeCompare(provided[:], v.hash) == 1
}

// NewAgentRouter exposes only the fixed firewall-management API required by
// the controller. It deliberately has no browser UI, users, authentication
// sessions, host inventory, access-key management, or arbitrary proxy route.
// keyHash must be SHA-256(agent plaintext key); the plaintext is never stored
// by the agent.
func NewAgentRouter(h *Handler, keyHash []byte) http.Handler {
	return NewAgentRouterWithVerifier(h, NewAgentKeyVerifier(keyHash))
}

func NewAgentRouterWithVerifier(h *Handler, verifier *AgentKeyVerifier) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", h.HealthCheck)
	mux.HandleFunc("/api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.ListRules(w, r)
		case http.MethodPost:
			h.CreateRule(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
		}
	})
	mux.HandleFunc("/api/v1/rules/batch-delete", postOnly(h.BatchDeleteRules))
	mux.HandleFunc("/api/v1/docker/whitelist/batch", postOnly(h.CreateDockerWhitelistBatch))
	mux.HandleFunc("/api/v1/rules/reorder", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use PUT")
			return
		}
		h.ReorderRules(w, r)
	})
	mux.HandleFunc("/api/v1/rules/", func(w http.ResponseWriter, r *http.Request) {
		id, action := extractRulePath(r.URL.Path)
		if id == "" {
			respondError(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		switch {
		case action == "/toggle" && r.Method == http.MethodPost:
			h.ToggleRule(w, r)
		case action == "" && r.Method == http.MethodGet:
			h.GetRule(w, r)
		case action == "" && r.Method == http.MethodPut:
			h.UpdateRule(w, r)
		case action == "" && r.Method == http.MethodDelete:
			h.DeleteRule(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid method")
		}
	})
	mux.HandleFunc("/api/v1/system/status", getOnly(h.GetSystemInfo))
	mux.HandleFunc("/api/v1/system/chains", getOnly(h.GetChains))
	mux.HandleFunc("/api/v1/system/chains/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || extractChainPath(r.URL.Path) == "" {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET with a chain name")
			return
		}
		h.GetChainRules(w, r)
	})
	mux.HandleFunc("/api/v1/system/backup", getOnly(h.BackupRules))
	mux.HandleFunc("/api/v1/system/restore", postOnly(h.RestoreRules))
	mux.HandleFunc("/api/v1/system/managed-rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use DELETE")
			return
		}
		h.ClearManagedRules(w, r)
	})
	mux.HandleFunc("/api/v1/system/audit", getOnly(h.GetAuditEvents))
	mux.HandleFunc("/api/v1/system/rollback", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.GetRollbackStatus(w, r)
		case http.MethodPost:
			h.RollbackLastChange(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
		}
	})
	mux.HandleFunc("/api/v1/docker/mappings", getOnly(h.GetDockerMappings))
	mux.HandleFunc("/api/v1/docker/diagnostics", getOnly(h.GetDockerDiagnostics))
	mux.HandleFunc("/api/v1/docker/whitelist", postOnly(h.CreateDockerWhitelist))

	var handler http.Handler = mux
	handler = agentMiddleware(handler, h, verifier)
	return handler
}

func agentMiddleware(handler http.Handler, h *Handler, verifier *AgentKeyVerifier) http.Handler {
	handler = changeAuditMiddleware(h, nil, nil, nil)(handler)
	handler = agentKeyMiddleware(verifier)(handler)
	handler = rateLimitMiddleware(600, time.Minute)(handler)
	handler = recoveryMiddleware(handler)
	handler = loggingMiddleware(handler)
	handler = requestIDMiddleware(handler)
	return handler
}

func getOnly(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		handler(w, r)
	}
}

func postOnly(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		handler(w, r)
	}
}

func agentKeyMiddleware(verifier *AgentKeyVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/health" {
				next.ServeHTTP(w, r)
				return
			}
			if verifier == nil || !verifier.Valid(r.Header.Get("X-API-Key")) {
				respondError(w, http.StatusUnauthorized, "agent_unauthorized", "valid agent key required")
				return
			}
			ctx := context.WithValue(r.Context(), apiKeyAuthKey, true)
			if identity, ok := trustedForwardedAuditIdentity(r); ok {
				ctx = context.WithValue(ctx, forwardedAuditIdentityKey, identity)
				setRequestLogActor(r, identity.Actor+"/"+identity.Role)
			} else {
				setRequestLogActor(r, "api-key/admin")
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func trustedForwardedAuditIdentity(r *http.Request) (*forwardedAuditIdentity, bool) {
	encodedActor := strings.TrimSpace(r.Header.Get(fleet.AuditActorHeader))
	actorBytes, err := base64.RawURLEncoding.DecodeString(encodedActor)
	if err != nil {
		return nil, false
	}
	actor := strings.TrimSpace(string(actorBytes))
	role := strings.TrimSpace(r.Header.Get(fleet.AuditRoleHeader))
	remoteIP := strings.TrimSpace(r.Header.Get(fleet.AuditRemoteIPHeader))
	if actor == "" || len(actorBytes) > 128 || !utf8.ValidString(actor) || strings.ContainsAny(actor, "\r\n") {
		return nil, false
	}
	if role != "admin" && role != "user" {
		return nil, false
	}
	if net.ParseIP(remoteIP) == nil {
		return nil, false
	}
	return &forwardedAuditIdentity{Actor: actor, Role: role, RemoteIP: remoteIP}, true
}
