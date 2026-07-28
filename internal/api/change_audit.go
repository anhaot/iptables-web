package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"iptables-web/internal/change"
	appLog "iptables-web/internal/logging"
	"iptables-web/internal/store"
)

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *auditResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func (w *auditResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func changeAuditMiddleware(h *Handler, users *store.UserStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.changes == nil || !isMutationRequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			h.changeMu.Lock()
			defer h.changeMu.Unlock()
			beforeRules, _ := h.store.All()
			beforeUsers := users.List()
			recorder := &auditResponseWriter{ResponseWriter: w}
			next.ServeHTTP(recorder, r)
			if recorder.status == 0 {
				recorder.status = http.StatusOK
			}
			afterRules, _ := h.store.All()
			afterUsers := users.List()
			ruleChanges := change.DiffRules(beforeRules, afterRules)
			userChanges := change.DiffUsers(beforeUsers, afterUsers)
			actor, role := auditActor(r)
			event := change.AuditEvent{
				CreatedAt:   time.Now(),
				RequestID:   requestIDFromContext(r),
				Actor:       actor,
				Role:        role,
				RemoteIP:    remoteRequestIP(r.RemoteAddr),
				Method:      r.Method,
				Path:        r.URL.Path,
				Action:      auditAction(r),
				Status:      recorder.status,
				RuleChanges: ruleChanges,
				UserChanges: userChanges,
			}
			if err := h.changes.Record(event); err != nil {
				appLog.Errorf("write change audit: %v", err)
			}
			if recorder.status < 400 && len(ruleChanges) > 0 && isRollbackEligible(r.URL.Path) {
				if _, err := h.changes.SaveRollback(event.Action, actor, beforeRules); err != nil {
					appLog.Errorf("save rollback window: %v", err)
				}
			}
		})
	}
}

func isMutationRequest(r *http.Request) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		return false
	}
	path := r.URL.Path
	return strings.HasPrefix(path, "/api/v1/rules") ||
		strings.HasPrefix(path, "/api/v1/users") ||
		path == "/api/v1/auth/password" ||
		path == "/api/v1/docker/whitelist" ||
		path == "/api/v1/system/restore" ||
		path == "/api/v1/system/managed-rules" ||
		path == "/api/v1/system/rollback"
}

func isRollbackEligible(path string) bool {
	return strings.HasPrefix(path, "/api/v1/rules") ||
		path == "/api/v1/docker/whitelist" ||
		path == "/api/v1/system/restore" ||
		path == "/api/v1/system/managed-rules" ||
		path == "/api/v1/system/rollback"
}

func auditActor(r *http.Request) (string, string) {
	if sess, ok := r.Context().Value(sessionKey).(*store.Session); ok {
		return sess.Username, sess.Role
	}
	if apiKey, _ := r.Context().Value(apiKeyAuthKey).(bool); apiKey {
		return "api-key", "admin"
	}
	if disabled, _ := r.Context().Value(authDisabledKey).(bool); disabled {
		return "auth-disabled", "admin"
	}
	return "anonymous", ""
}

func requestIDFromContext(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey).(string)
	return id
}

func auditAction(r *http.Request) string {
	path := r.URL.Path
	switch {
	case path == "/api/v1/rules" && r.Method == http.MethodPost:
		return "create_rule"
	case path == "/api/v1/rules/reorder":
		return "reorder_rules"
	case strings.HasSuffix(path, "/toggle"):
		return "toggle_rule"
	case strings.HasPrefix(path, "/api/v1/rules/") && r.Method == http.MethodPut:
		return "update_rule"
	case strings.HasPrefix(path, "/api/v1/rules/") && r.Method == http.MethodDelete:
		return "delete_rule"
	case path == "/api/v1/docker/whitelist":
		return "create_docker_whitelist"
	case path == "/api/v1/system/restore":
		return "restore_firewall"
	case path == "/api/v1/system/managed-rules":
		return "clear_managed_rules"
	case path == "/api/v1/system/rollback":
		return "rollback_change"
	case path == "/api/v1/auth/password":
		return "change_password"
	case strings.HasPrefix(path, "/api/v1/users"):
		return "manage_user"
	default:
		return strings.ToLower(r.Method) + " " + path
	}
}

func (h *Handler) GetAuditEvents(w http.ResponseWriter, r *http.Request) {
	if h.changes == nil {
		respondError(w, http.StatusServiceUnavailable, "audit_unavailable", "change audit is not configured")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	if r.URL.Query().Get("download") == "1" {
		limit = -1
	}
	events, err := h.changes.List(limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "audit_error", err.Error())
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="iptables-web-audit-%s.json"`, time.Now().Format("20060102-150405")))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(events)
		return
	}
	respondOK(w, events)
}

type rollbackRequest struct {
	ID string `json:"id"`
}

func (h *Handler) GetRollbackStatus(w http.ResponseWriter, r *http.Request) {
	if h.changes == nil {
		respondError(w, http.StatusServiceUnavailable, "rollback_unavailable", "rollback is not configured")
		return
	}
	state, err := h.changes.RollbackStatus()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "rollback_error", err.Error())
		return
	}
	if state == nil {
		respondOK(w, map[string]interface{}{"available": false})
		return
	}
	respondOK(w, map[string]interface{}{
		"available":  true,
		"id":         state.ID,
		"created_at": state.CreatedAt,
		"expires_at": state.ExpiresAt,
		"action":     state.Action,
		"actor":      state.Actor,
		"rule_count": len(state.Rules),
	})
}

func (h *Handler) RollbackLastChange(w http.ResponseWriter, r *http.Request) {
	if h.changes == nil {
		respondError(w, http.StatusServiceUnavailable, "rollback_unavailable", "rollback is not configured")
		return
	}
	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()
	var req rollbackRequest
	if err := decodeJSONBody(w, r, &req, defaultJSONBodyLimit); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	state, err := h.changes.RollbackStatus()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "rollback_error", err.Error())
		return
	}
	if state == nil {
		respondError(w, http.StatusConflict, "rollback_expired", "rollback window is unavailable or expired")
		return
	}
	if req.ID == "" || req.ID != state.ID {
		respondError(w, http.StatusConflict, "rollback_changed", "rollback target changed; refresh and confirm again")
		return
	}

	current := h.snapshotRules()
	if err := h.executor.DeleteRules(current); err != nil {
		_ = h.executor.SyncRules(current)
		respondError(w, http.StatusInternalServerError, "rollback_error", "remove current managed rules: "+err.Error())
		return
	}
	if err := h.store.ReplaceAll(state.Rules); err != nil {
		_ = h.executor.SyncRules(current)
		respondError(w, http.StatusInternalServerError, "rollback_error", err.Error())
		return
	}
	if err := h.store.Save(); err != nil {
		_ = h.store.ReplaceAll(current)
		_ = h.store.Save()
		_ = h.executor.SyncRules(current)
		respondError(w, http.StatusInternalServerError, "rollback_error", err.Error())
		return
	}
	if err := h.executor.SyncRules(state.Rules); err != nil {
		_ = h.executor.DeleteRules(state.Rules)
		_ = h.store.ReplaceAll(current)
		_ = h.store.Save()
		_ = h.executor.SyncRules(current)
		respondError(w, http.StatusInternalServerError, "rollback_error", err.Error())
		return
	}
	if err := h.executor.VerifyRules(state.Rules); err != nil {
		_ = h.executor.DeleteRules(state.Rules)
		_ = h.store.ReplaceAll(current)
		_ = h.store.Save()
		_ = h.executor.SyncRules(current)
		respondError(w, http.StatusInternalServerError, "rollback_error", err.Error())
		return
	}
	respondOK(w, map[string]interface{}{
		"restored_rules": len(state.Rules),
		"rolled_back":    state.Action,
	})
}
