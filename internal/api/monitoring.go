package api

import (
	"iptables-web/internal/change"
	appLog "iptables-web/internal/logging"
	"iptables-web/internal/model"
	"net/http"
)

func (h *HostHandler) monitoringPolicy(w http.ResponseWriter, r *http.Request, audit *change.Manager) {
	switch r.Method {
	case http.MethodGet:
		respondOK(w, h.monitoring.Get())
	case http.MethodPut:
		adminRequired()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var policy model.MonitoringPolicy
			if err := decodeJSONBody(w, r, &policy, defaultJSONBodyLimit); err != nil {
				respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
				return
			}
			if err := policy.Validate(); err != nil {
				respondError(w, http.StatusBadRequest, "validation_error", err.Error())
				return
			}
			h.monitoringMu.Lock()
			defer h.monitoringMu.Unlock()
			before := h.monitoring.Get()
			if err := h.monitoring.Update(policy); err != nil {
				respondError(w, http.StatusInternalServerError, "store_error", "无法保存在线检测设置")
				return
			}
			if audit != nil {
				actor, role := auditActor(r)
				event := change.AuditEvent{Actor: actor, Role: role, RemoteIP: auditRemoteIP(r), RequestID: requestIDFromContext(r), Method: r.Method, Path: r.URL.Path, Action: "update_monitoring_policy", Status: http.StatusOK, MonitoringPolicyBefore: &before, MonitoringPolicyAfter: &policy}
				if err := audit.Record(event); err != nil {
					appLog.Errorf("write monitoring policy audit: %v", err)
				}
			}
			respondOK(w, h.monitoring.Get())
		})).ServeHTTP(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or PUT")
	}
}
