package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"iptables-web/internal/change"
	appLog "iptables-web/internal/logging"
	"iptables-web/internal/model"
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

func changeAuditMiddleware(h *Handler, users *store.UserStore, hosts *store.HostStore, accessKeys *store.APIKeyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.changes == nil || !isMutationRequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			trackLocalSnapshot := mutationChangesLocalSnapshot(r)
			trackHostSnapshot := mutationChangesHostSnapshot(r)
			trackAccessKeySnapshot := strings.HasPrefix(r.URL.Path, "/api/v1/access-keys")
			trackPolicySnapshot := r.URL.Path == "/api/v1/security-policy"
			trackSnapshot := trackLocalSnapshot || trackHostSnapshot || trackAccessKeySnapshot || trackPolicySnapshot
			if trackSnapshot {
				h.changeMu.Lock()
				defer h.changeMu.Unlock()
			}
			var beforeRules []*model.Rule
			var beforeUsers []model.UserResponse
			var beforeHosts []model.ManagedHostResponse
			var beforeAccessKeys []model.AccessKeyResponse
			var beforePolicy *model.AdminSecurityPolicy
			if trackLocalSnapshot {
				beforeRules, _ = h.store.All()
				if users != nil {
					beforeUsers = users.List()
				}
			}
			if trackHostSnapshot && hosts != nil {
				beforeHosts = hosts.List()
			}
			if trackAccessKeySnapshot && accessKeys != nil {
				beforeAccessKeys = accessKeys.List()
			}
			if trackPolicySnapshot && users != nil {
				policy := users.AdminSecurityPolicy()
				beforePolicy = &policy
			}
			recorder := &auditResponseWriter{ResponseWriter: w}
			next.ServeHTTP(recorder, r)
			if recorder.status == 0 {
				recorder.status = http.StatusOK
			}
			var ruleChanges []change.RuleChange
			var userChanges []change.UserChange
			if trackLocalSnapshot {
				afterRules, _ := h.store.All()
				var afterUsers []model.UserResponse
				if users != nil {
					afterUsers = users.List()
				}
				ruleChanges = change.DiffRules(beforeRules, afterRules)
				userChanges = change.DiffUsers(beforeUsers, afterUsers)
			}
			var hostChanges []change.HostChange
			var accessKeyChanges []change.AccessKeyChange
			var afterPolicy *model.AdminSecurityPolicy
			if trackHostSnapshot && hosts != nil {
				hostChanges = change.DiffHosts(beforeHosts, hosts.List())
			}
			if trackAccessKeySnapshot && accessKeys != nil {
				accessKeyChanges = change.DiffAccessKeys(beforeAccessKeys, accessKeys.List())
			}
			if trackPolicySnapshot && users != nil {
				policy := users.AdminSecurityPolicy()
				if beforePolicy == nil || !reflect.DeepEqual(*beforePolicy, policy) {
					afterPolicy = &policy
				} else {
					beforePolicy = nil
				}
			}
			actor, role := auditActor(r)
			event := change.AuditEvent{
				CreatedAt:            time.Now(),
				RequestID:            requestIDFromContext(r),
				Actor:                actor,
				Role:                 role,
				RemoteIP:             auditRemoteIP(r),
				Method:               r.Method,
				Path:                 r.URL.Path,
				Action:               auditAction(r),
				Status:               recorder.status,
				RuleChanges:          ruleChanges,
				UserChanges:          userChanges,
				HostChanges:          hostChanges,
				AccessKeyChanges:     accessKeyChanges,
				SecurityPolicyBefore: beforePolicy,
				SecurityPolicyAfter:  afterPolicy,
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

func mutationChangesHostSnapshot(r *http.Request) bool {
	if r.URL.Path == "/api/v1/agent-enrollments/approve" {
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/hosts/") || strings.Contains(r.URL.Path, "/api/") || r.URL.Path == "/api/v1/hosts/batch/rules" {
		return false
	}
	return r.Method == http.MethodPut || r.Method == http.MethodDelete
}

func mutationChangesLocalSnapshot(r *http.Request) bool {
	path := r.URL.Path
	return strings.HasPrefix(path, "/api/v1/rules") ||
		strings.HasPrefix(path, "/api/v1/users") ||
		path == "/api/v1/security-policy" ||
		path == "/api/v1/auth/password" ||
		path == "/api/v1/docker/whitelist" ||
		path == "/api/v1/system/restore" ||
		path == "/api/v1/system/managed-rules" ||
		path == "/api/v1/system/rollback"
}

func isMutationRequest(r *http.Request) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		return false
	}
	path := r.URL.Path
	return strings.HasPrefix(path, "/api/v1/rules") ||
		strings.HasPrefix(path, "/api/v1/hosts") ||
		path == "/api/v1/agent-enrollments/approve" ||
		path == "/api/v1/agent-enrollments/reject" ||
		strings.HasPrefix(path, "/api/v1/access-keys") ||
		strings.HasPrefix(path, "/api/v1/users") ||
		path == "/api/v1/security-policy" ||
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
	if identity, ok := r.Context().Value(forwardedAuditIdentityKey).(*forwardedAuditIdentity); ok && identity != nil {
		return identity.Actor, identity.Role
	}
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

func auditRemoteIP(r *http.Request) string {
	if identity, ok := r.Context().Value(forwardedAuditIdentityKey).(*forwardedAuditIdentity); ok && identity != nil {
		return identity.RemoteIP
	}
	return remoteRequestIP(r.RemoteAddr)
}

func requestIDFromContext(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey).(string)
	return id
}

func auditAction(r *http.Request) string {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/api/v1/agent-enrollments/approve"):
		return "approve_agent_enrollment"
	case strings.HasPrefix(path, "/api/v1/agent-enrollments/reject"):
		return "reject_agent_enrollment"
	case strings.HasPrefix(path, "/api/v1/access-keys"):
		return "manage_access_key"
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
	case path == "/api/v1/security-policy":
		return "update_security_policy"
	case strings.HasPrefix(path, "/api/v1/hosts"):
		return "manage_remote_host"
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
