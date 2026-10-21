package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"iptables-web/internal/fleet"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

const (
	maxHostProxyBody          = 16 * 1024 * 1024
	maxBatchRuleResponseBytes = 256 * 1024
)

var hostIDPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)

type HostHandler struct {
	store        *store.HostStore
	users        *store.UserStore
	client       *fleet.Client
	monitoring   *store.MonitoringStore
	probeMu      sync.Mutex
	monitoringMu sync.Mutex
	probes       map[string]*hostProbe
}

type hostRequest struct {
	Name                 string `json:"name"`
	Group                string `json:"group"`
	BaseURL              string `json:"base_url"`
	CAPEM                string `json:"ca_pem"`
	ClearCA              bool   `json:"clear_ca,omitempty"`
	Enabled              *bool  `json:"enabled,omitempty"`
	ProbeIntervalSeconds *int   `json:"probe_interval_seconds,omitempty"`
	OfflineAfterSeconds  *int   `json:"offline_after_seconds,omitempty"`
}

func NewHostHandler(hostStore *store.HostStore, userStores ...*store.UserStore) *HostHandler {
	var users *store.UserStore
	if len(userStores) > 0 {
		users = userStores[0]
	}
	return &HostHandler{store: hostStore, users: users, client: fleet.NewClient(20 * time.Second), monitoring: store.NewMonitoringStore(""), probes: make(map[string]*hostProbe)}
}

func (h *HostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		respondError(w, http.StatusServiceUnavailable, "fleet_unavailable", "multi-host management is not configured")
		return
	}
	if r.URL.Path == "/api/v1/hosts" || r.URL.Path == "/api/v1/hosts/" {
		switch r.Method {
		case http.MethodGet:
			respondOK(w, h.authorizedHosts(r))
		case http.MethodPost:
			respondError(w, http.StatusMethodNotAllowed, "agent_enrollment_required", "install the Agent and approve its signed enrollment request")
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		}
		return
	}
	if r.URL.Path == "/api/v1/hosts/batch/rules" {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		h.batchCreateRule(w, r)
		return
	}

	id, suffix := splitHostPath(r.URL.Path)
	if id == "" || !hostIDPattern.MatchString(id) {
		respondError(w, http.StatusNotFound, "not_found", "host not found")
		return
	}
	if suffix == "" && (r.Method == http.MethodPut || r.Method == http.MethodDelete) {
		// Inventory lifecycle remains a controller-administrator operation.
	} else if !h.hostAccessAllowed(r, id) {
		// Return 404 so an unassigned user cannot enumerate host identifiers.
		respondError(w, http.StatusNotFound, "not_found", "host not found")
		return
	}
	switch {
	case suffix == "":
		switch r.Method {
		case http.MethodGet:
			host, err := h.store.Get(id)
			if err != nil {
				respondError(w, http.StatusNotFound, "not_found", err.Error())
				return
			}
			respondOK(w, host.ToResponse())
		case http.MethodPut:
			adminRequired()(http.HandlerFunc(h.updateHost)).ServeHTTP(w, r)
		case http.MethodDelete:
			adminRequired()(http.HandlerFunc(h.deleteHost)).ServeHTTP(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET, PUT or DELETE")
		}
	case suffix == "/probe":
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		h.probeHost(w, r, id)
	case strings.HasPrefix(suffix, "/api/"):
		remotePath := "/api/v1/" + strings.TrimPrefix(suffix, "/api/")
		if !allowedRemoteOperation(r.Method, remotePath) {
			respondError(w, http.StatusForbidden, "remote_path_denied", "remote API path is not allowed")
			return
		}
		h.proxyHost(w, r, id, remotePath)
	default:
		respondError(w, http.StatusNotFound, "not_found", "host endpoint not found")
	}
}

func (h *HostHandler) updateHost(w http.ResponseWriter, r *http.Request) {
	id, _ := splitHostPath(r.URL.Path)
	existing, err := h.store.Get(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	var req hostRequest
	if err := decodeJSONBody(w, r, &req, 512*1024); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.Enabled == nil {
		enabled := existing.Enabled
		req.Enabled = &enabled
	}
	if strings.TrimSpace(req.BaseURL) != "" && strings.TrimRight(strings.TrimSpace(req.BaseURL), "/") != existing.BaseURL {
		respondError(w, http.StatusBadRequest, "agent_enrollment_required", "Agent address changes require a signed enrollment request")
		return
	}
	req.BaseURL = existing.BaseURL
	if req.ProbeIntervalSeconds == nil {
		value := existing.ProbeIntervalSeconds
		req.ProbeIntervalSeconds = &value
	}
	if req.OfflineAfterSeconds == nil {
		value := existing.OfflineAfterSeconds
		req.OfflineAfterSeconds = &value
	}
	if strings.TrimSpace(req.CAPEM) == "" && existing.CAPEM != "" && !req.ClearCA {
		req.CAPEM = existing.CAPEM
	}
	host, err := h.validatedHost(req, id)
	if err != nil {
		respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	host.CreatedAt = existing.CreatedAt
	host.AgentID = existing.AgentID
	host.AgentPublicKey = existing.AgentPublicKey
	host.AgentLastSeenAt = existing.AgentLastSeenAt
	if err := h.store.UpdateMetadata(existing, host); err != nil {
		respondError(w, http.StatusBadRequest, "host_store_error", err.Error())
		return
	}
	saved, err := h.store.Get(id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "host_store_error", err.Error())
		return
	}
	respondOK(w, saved.ToResponse())
}

func (h *HostHandler) deleteHost(w http.ResponseWriter, r *http.Request) {
	id, _ := splitHostPath(r.URL.Path)
	if err := h.store.Delete(id); err != nil {
		respondError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	h.probeMu.Lock()
	delete(h.probes, id)
	h.probeMu.Unlock()
	if h.users != nil {
		// The host has already been deleted at this point. A stale assignment is
		// harmless (all access checks also require a live host), so do not turn a
		// successful deletion into a misleading 500 response if pruning fails.
		_ = h.users.RemoveHostAssignment(id)
	}
	respondNoContent(w)
}

func (h *HostHandler) authorizedHosts(r *http.Request) []model.ManagedHostResponse {
	hosts := h.store.List()
	if controllerWideAccess(r) {
		return hosts
	}
	sess, _ := r.Context().Value(sessionKey).(*store.Session)
	if sess == nil {
		return []model.ManagedHostResponse{}
	}
	allowed := make(map[string]bool, len(sess.HostIDs))
	for _, id := range sess.HostIDs {
		allowed[id] = true
	}
	allowedGroups := make(map[string]bool, len(sess.HostGroups))
	for _, group := range sess.HostGroups {
		allowedGroups[strings.ToLower(strings.TrimSpace(group))] = true
	}
	result := make([]model.ManagedHostResponse, 0, len(hosts))
	for _, host := range hosts {
		if allowed[host.ID] || (host.Group != "" && allowedGroups[strings.ToLower(strings.TrimSpace(host.Group))]) {
			result = append(result, host)
		}
	}
	return result
}

func controllerWideAccess(r *http.Request) bool {
	if allowed, _ := r.Context().Value(apiKeyAuthKey).(bool); allowed {
		return true
	}
	if disabled, _ := r.Context().Value(authDisabledKey).(bool); disabled {
		return true
	}
	sess, _ := r.Context().Value(sessionKey).(*store.Session)
	return sess != nil && sess.Role == "admin"
}

func (h *HostHandler) hostAccessAllowed(r *http.Request, hostID string) bool {
	if controllerWideAccess(r) {
		return true
	}
	sess, _ := r.Context().Value(sessionKey).(*store.Session)
	if sess == nil || sess.Role != "user" {
		return false
	}
	for _, id := range sess.HostIDs {
		if id == hostID {
			return true
		}
	}
	host, err := h.store.Get(hostID)
	if err != nil || strings.TrimSpace(host.Group) == "" {
		return false
	}
	for _, group := range sess.HostGroups {
		if strings.EqualFold(strings.TrimSpace(group), strings.TrimSpace(host.Group)) {
			return true
		}
	}
	return false
}

func (h *HostHandler) validatedHost(req hostRequest, id string) (*model.ManagedHost, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Group = strings.TrimSpace(req.Group)
	req.BaseURL = strings.TrimSpace(req.BaseURL)
	if req.Name == "" || len([]rune(req.Name)) > 64 {
		return nil, fmt.Errorf("host name is required and must not exceed 64 characters")
	}
	if len([]rune(req.Group)) > 64 {
		return nil, fmt.Errorf("host group must not exceed 64 characters")
	}
	if len(req.CAPEM) > 256*1024 {
		return nil, fmt.Errorf("CA PEM exceeds 256KB limit")
	}
	parsed, err := url.Parse(req.BaseURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("base_url must be an absolute URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("base_url cannot contain credentials, query or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf("base_url cannot contain a path")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("base_url must use HTTP or HTTPS")
	}
	parsed.Path = ""
	parsed.RawPath = ""
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if id == "" {
		id, err = newHostID()
		if err != nil {
			return nil, fmt.Errorf("generate host ID: %w", err)
		}
	}
	host := &model.ManagedHost{ID: id, Name: req.Name, Group: req.Group, BaseURL: strings.TrimRight(parsed.String(), "/"), CAPEM: strings.TrimSpace(req.CAPEM), Enabled: enabled}
	if req.ProbeIntervalSeconds != nil {
		host.ProbeIntervalSeconds = *req.ProbeIntervalSeconds
	}
	if req.OfflineAfterSeconds != nil {
		host.OfflineAfterSeconds = *req.OfflineAfterSeconds
	}
	if err := model.ValidateMonitoringOverrides(host.ProbeIntervalSeconds, host.OfflineAfterSeconds); err != nil {
		return nil, err
	}
	return host, nil
}

func (h *HostHandler) proxyHost(w http.ResponseWriter, r *http.Request, id, remotePath string) {
	host, key, err := h.store.GetWithAPIKey(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	var body []byte
	if r.Body != nil && r.Method != http.MethodGet {
		r.Body = http.MaxBytesReader(w, r.Body, maxHostProxyBody)
		body, err = io.ReadAll(r.Body)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid_body", err.Error())
			return
		}
	}
	resp, err := h.client.DoAs(r.Context(), host, key, r.Method, remotePath, r.URL.RawQuery, body, r.Header.Get("Content-Type"), remoteAuditIdentity(r))
	if err != nil {
		respondError(w, http.StatusBadGateway, "remote_unreachable", err.Error())
		return
	}
	// A remote credential failure must not look like an expired controller
	// session to the browser, otherwise the UI would clear the valid local
	// login token and redirect to the login page.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		respondError(w, http.StatusBadGateway, "remote_auth_failed", "remote host rejected its configured API key")
		return
	}
	if r.Method == http.MethodPost &&
		(remotePath == "/api/v1/docker/whitelist/batch" || remotePath == "/api/v1/rules/batch-delete") &&
		(resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) {
		respondError(w, http.StatusConflict, "agent_upgrade_required", "目标 Agent 不支持批量操作，请使用完整发布包升级该主机的 Agent 后重试")
		return
	}
	copyRemoteHeader(w.Header(), resp.Header, "Content-Type", "Content-Disposition")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(resp.Body)
}

type batchRuleRequest struct {
	HostIDs []string        `json:"host_ids"`
	Rule    json.RawMessage `json:"rule"`
}

type batchRuleResult struct {
	HostID  string          `json:"host_id"`
	Status  int             `json:"status"`
	Success bool            `json:"success"`
	Body    json.RawMessage `json:"body,omitempty"`
	Error   string          `json:"error,omitempty"`
}

func (h *HostHandler) batchCreateRule(w http.ResponseWriter, r *http.Request) {
	var req batchRuleRequest
	if err := decodeJSONBody(w, r, &req, 512*1024); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if len(req.HostIDs) == 0 || len(req.HostIDs) > 100 || len(req.Rule) == 0 {
		respondError(w, http.StatusBadRequest, "validation_error", "host_ids (1-100) and rule are required")
		return
	}
	seen := make(map[string]bool, len(req.HostIDs))
	// Validate the entire batch before starting any remote mutation. An invalid
	// later item must not leave earlier hosts changed behind a 400/403 response.
	for _, id := range req.HostIDs {
		if !hostIDPattern.MatchString(id) || seen[id] {
			respondError(w, http.StatusBadRequest, "validation_error", "host_ids contain an invalid or duplicate id")
			return
		}
		seen[id] = true
		if !h.hostAccessAllowed(r, id) {
			respondError(w, http.StatusForbidden, "host_forbidden", "one or more hosts are outside the user's authorization scope")
			return
		}
	}
	results := make([]batchRuleResult, len(req.HostIDs))
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	for i, id := range req.HostIDs {
		wg.Add(1)
		go func(index int, hostID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			result := batchRuleResult{HostID: hostID}
			host, key, err := h.store.GetWithAPIKey(hostID)
			if err != nil {
				result.Error = err.Error()
				results[index] = result
				return
			}
			resp, err := h.client.DoWithResponseLimitAs(r.Context(), host, key, http.MethodPost, "/api/v1/rules", "", req.Rule, "application/json", maxBatchRuleResponseBytes, remoteAuditIdentity(r))
			if err != nil {
				result.Error = err.Error()
				results[index] = result
				return
			}
			result.Status = resp.StatusCode
			result.Success = resp.StatusCode >= 200 && resp.StatusCode < 300
			if json.Valid(resp.Body) {
				result.Body = append(json.RawMessage(nil), resp.Body...)
			} else if !result.Success {
				result.Error = strings.TrimSpace(string(resp.Body))
			}
			results[index] = result
		}(i, id)
	}
	wg.Wait()
	respondOK(w, results)
}

func remoteAuditIdentity(r *http.Request) fleet.AuditIdentity {
	actor, role := auditActor(r)
	return fleet.AuditIdentity{
		Actor:     actor,
		Role:      role,
		RemoteIP:  remoteRequestIP(r.RemoteAddr),
		RequestID: requestIDFromContext(r),
	}
}

func splitHostPath(path string) (string, string) {
	rest := strings.TrimPrefix(path, "/api/v1/hosts/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], "/" + parts[1]
}

func allowedRemoteOperation(method, path string) bool {
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut && method != http.MethodDelete {
		return false
	}
	if strings.Contains(path, "//") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	if path == "/api/v1/rules" {
		return method == http.MethodGet || method == http.MethodPost
	}
	if path == "/api/v1/rules/batch-delete" || path == "/api/v1/docker/whitelist/batch" {
		return method == http.MethodPost
	}
	if path == "/api/v1/rules/reorder" {
		return method == http.MethodPut
	}
	if strings.HasPrefix(path, "/api/v1/rules/") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/rules/"), "/")
		if len(parts) == 2 && parts[0] != "" && parts[1] == "toggle" {
			return method == http.MethodPost
		}
		return len(parts) == 1 && parts[0] != "" && (method == http.MethodGet || method == http.MethodPut || method == http.MethodDelete)
	}
	readOnly := map[string]bool{
		"/api/v1/health": true, "/api/v1/system/status": true,
		"/api/v1/system/chains": true, "/api/v1/docker/mappings": true,
		"/api/v1/docker/diagnostics": true, "/api/v1/system/backup": true,
		"/api/v1/system/audit": true,
	}
	if readOnly[path] {
		return method == http.MethodGet
	}
	if strings.HasPrefix(path, "/api/v1/system/chains/") && strings.HasSuffix(path, "/rules") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/system/chains/"), "/")
		return len(parts) == 2 && parts[0] != "" && parts[1] == "rules" && method == http.MethodGet
	}
	if path == "/api/v1/docker/whitelist" {
		return method == http.MethodPost
	}
	if path == "/api/v1/system/restore" {
		return method == http.MethodPost
	}
	if path == "/api/v1/system/managed-rules" {
		return method == http.MethodDelete
	}
	if path == "/api/v1/system/rollback" {
		return method == http.MethodGet || method == http.MethodPost
	}
	return false
}

func copyRemoteHeader(dst, src http.Header, names ...string) {
	for _, name := range names {
		if value := src.Get(name); value != "" {
			dst.Set(name, value)
		}
	}
}

func newHostID() (string, error) {
	data := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}
