package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"iptables-web/internal/enrollment"
	"iptables-web/internal/fleet"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

const (
	maxPendingEnrollments = 1000
	pendingEnrollmentTTL  = 10 * time.Minute
	rejectedEnrollmentTTL = 24 * time.Hour
)

type PendingEnrollmentResponse struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Group          string    `json:"group,omitempty"`
	BaseURL        string    `json:"base_url"`
	SourceIP       string    `json:"source_ip"`
	ExistingHostID string    `json:"existing_host_id,omitempty"`
	RequestedAt    time.Time `json:"requested_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
}

type pendingEnrollment struct {
	PendingEnrollmentResponse
	PublicKey string
	AgentKey  string
	LastNonce string
}

type EnrollmentHandler struct {
	mu       sync.Mutex
	hosts    *store.HostStore
	client   *fleet.Client
	pending  map[string]*pendingEnrollment
	rejected map[string]time.Time
	limiter  *rateLimiter
}

func NewEnrollmentHandler(hosts *store.HostStore) *EnrollmentHandler {
	return &EnrollmentHandler{
		hosts: hosts, client: fleet.NewClient(8 * time.Second),
		pending: make(map[string]*pendingEnrollment), rejected: make(map[string]time.Time),
		limiter: newRateLimiter(30, time.Minute),
	}
}

func (h *EnrollmentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.hosts == nil {
		respondError(w, http.StatusServiceUnavailable, "enrollment_unavailable", "Agent enrollment is not configured")
		return
	}
	switch r.URL.Path {
	case "/api/v1/agent-enrollments/register":
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		h.register(w, r)
	case "/api/v1/agent-enrollments":
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		h.list(w)
	case "/api/v1/agent-enrollments/approve":
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		h.approve(w, r)
	case "/api/v1/agent-enrollments/reject":
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}
		h.reject(w, r)
	default:
		respondError(w, http.StatusNotFound, "not_found", "enrollment endpoint not found")
	}
}

func (h *EnrollmentHandler) register(w http.ResponseWriter, r *http.Request) {
	sourceIP := remoteRequestIP(r.RemoteAddr)
	if !h.limiter.allow(sourceIP) {
		w.Header().Set("Retry-After", "60")
		respondError(w, http.StatusTooManyRequests, "enrollment_rate_limited", "too many Agent registration requests")
		return
	}
	var req enrollment.Request
	if err := decodeJSONBody(w, r, &req, 64*1024); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_enrollment", err.Error())
		return
	}
	publicKey, err := req.Verify(time.Now(), 5*time.Minute)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_enrollment", err.Error())
		return
	}
	if err := validateEnrollmentFields(req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_enrollment", err.Error())
		return
	}
	candidate, err := NewHostHandler(h.hosts).validatedHost(hostRequest{Name: req.Name, Group: req.Group, BaseURL: req.BaseURL}, "")
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_enrollment", err.Error())
		return
	}
	boundURL, err := enrollmentURLForSource(candidate.BaseURL, sourceIP)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_enrollment", err.Error())
		return
	}
	candidate.BaseURL = boundURL
	req.BaseURL = boundURL

	if existing, err := h.hosts.GetByAgentID(req.AgentID); err == nil {
		if existing.AgentPublicKey != req.PublicKey {
			respondError(w, http.StatusConflict, "agent_identity_conflict", "Agent identity conflicts with a managed host")
			return
		}
		seenAt := time.Now().UTC()
		if err := h.hosts.MarkAgentSeen(req.AgentID, seenAt); err != nil {
			respondError(w, http.StatusInternalServerError, "host_store_error", err.Error())
			return
		}
		existing.AgentLastSeenAt = &seenAt
		if existing.BaseURL == candidate.BaseURL {
			if req.AgentKey != "" {
				probeCandidate := *candidate
				probeCandidate.CAPEM = existing.CAPEM
				probeCandidate.Enabled = true
				if err := h.verifyAgent(r.Context(), &probeCandidate, req.AgentKey); err != nil {
					respondError(w, http.StatusBadGateway, "agent_probe_failed", err.Error())
					return
				}
				if err := h.hosts.Update(existing, req.AgentKey); err != nil {
					respondError(w, http.StatusInternalServerError, "host_store_error", err.Error())
					return
				}
			}
			respondOK(w, map[string]string{"status": "approved"})
			return
		}
		if req.AgentKey == "" {
			respondOK(w, map[string]string{"status": "registration_required"})
			return
		}
		h.upsertPending(req, publicKey, sourceIP, existing.ID)
		respondOK(w, map[string]string{"status": "pending"})
		return
	}

	if req.AgentKey == "" {
		respondOK(w, map[string]string{"status": "registration_required"})
		return
	}
	status, ok := h.upsertPending(req, publicKey, sourceIP, "")
	if !ok {
		respondError(w, http.StatusServiceUnavailable, "enrollment_queue_full", "the pending Agent queue is full")
		return
	}
	respondOK(w, map[string]string{"status": status})
}

func enrollmentURLForSource(baseURL, sourceIP string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid Agent URL")
	}
	source := net.ParseIP(sourceIP)
	if source == nil {
		return "", fmt.Errorf("Agent request source is not an IP address")
	}
	port := parsed.Port()
	if port != "" {
		parsed.Host = net.JoinHostPort(source.String(), port)
	} else if source.To4() == nil {
		parsed.Host = "[" + source.String() + "]"
	} else {
		parsed.Host = source.String()
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func validateEnrollmentFields(req enrollment.Request) error {
	if len(req.AgentID) != 24 || !hostIDPattern.MatchString(req.AgentID) {
		return fmt.Errorf("invalid Agent ID")
	}
	if strings.TrimSpace(req.Name) == "" || len([]rune(req.Name)) > 64 {
		return fmt.Errorf("Agent name is required and must not exceed 64 characters")
	}
	if len([]rune(req.Group)) > 64 {
		return fmt.Errorf("Agent group must not exceed 64 characters")
	}
	if req.AgentKey != "" && (!strings.HasPrefix(req.AgentKey, "ipwa_") || len(req.AgentKey) > 128) {
		return fmt.Errorf("invalid Agent key")
	}
	return nil
}

func (h *EnrollmentHandler) upsertPending(req enrollment.Request, publicKey ed25519.PublicKey, sourceIP, existingHostID string) (string, bool) {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cleanupLocked(now)
	if until, rejected := h.rejected[req.AgentID]; rejected && now.Before(until) {
		return "rejected", true
	}
	if current := h.pending[req.AgentID]; current != nil {
		if current.PublicKey != enrollment.PublicKeyString(publicKey) {
			return "identity_conflict", false
		}
		if current.LastNonce == req.Nonce {
			return "pending", true
		}
		current.Name = req.Name
		current.Group = req.Group
		current.BaseURL = req.BaseURL
		current.SourceIP = sourceIP
		current.ExistingHostID = existingHostID
		current.AgentKey = req.AgentKey
		current.LastNonce = req.Nonce
		current.LastSeenAt = now
		return "pending", true
	}
	if len(h.pending) >= maxPendingEnrollments {
		return "queue_full", false
	}
	h.pending[req.AgentID] = &pendingEnrollment{
		PendingEnrollmentResponse: PendingEnrollmentResponse{
			ID: req.AgentID, Name: req.Name, Group: req.Group, BaseURL: req.BaseURL,
			SourceIP: sourceIP, ExistingHostID: existingHostID, RequestedAt: now, LastSeenAt: now,
		},
		PublicKey: enrollment.PublicKeyString(publicKey), AgentKey: req.AgentKey, LastNonce: req.Nonce,
	}
	return "pending", true
}

func (h *EnrollmentHandler) list(w http.ResponseWriter) {
	h.mu.Lock()
	h.cleanupLocked(time.Now())
	items := make([]PendingEnrollmentResponse, 0, len(h.pending))
	for _, item := range h.pending {
		items = append(items, item.PendingEnrollmentResponse)
	}
	h.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].RequestedAt.Before(items[j].RequestedAt) })
	respondOK(w, items)
}

type enrollmentBatchRequest struct {
	IDs       []string          `json:"ids"`
	CAPEMByID map[string]string `json:"ca_pem_by_id,omitempty"`
}

type enrollmentApprovalResult struct {
	ID      string                     `json:"id"`
	Success bool                       `json:"success"`
	Host    *model.ManagedHostResponse `json:"host,omitempty"`
	Error   string                     `json:"error,omitempty"`
}

func (h *EnrollmentHandler) approve(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeEnrollmentRequest(w, r)
	if !ok {
		return
	}
	ids := req.IDs
	h.mu.Lock()
	selected := make([]*pendingEnrollment, len(ids))
	for i, id := range ids {
		if item := h.pending[id]; item != nil {
			copy := *item
			selected[i] = &copy
		}
	}
	h.mu.Unlock()

	names := h.uniqueNames(selected)
	results := make([]enrollmentApprovalResult, len(ids))
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	for i, id := range ids {
		results[i].ID = id
		item := selected[i]
		if item == nil {
			results[i].Error = "pending Agent not found or expired"
			continue
		}
		wg.Add(1)
		go func(index int, pending *pendingEnrollment) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			result := h.approveOne(r.Context(), pending, names[pending.ID], req.CAPEMByID[pending.ID])
			results[index] = result
		}(i, item)
	}
	wg.Wait()
	respondOK(w, results)
}

func (h *EnrollmentHandler) approveOne(ctx context.Context, pending *pendingEnrollment, name, caPEM string) enrollmentApprovalResult {
	result := enrollmentApprovalResult{ID: pending.ID}
	hostID, err := newHostID()
	if err != nil {
		result.Error = "generate host ID: " + err.Error()
		return result
	}
	candidate := &model.ManagedHost{
		ID: hostID, Name: name, Group: pending.Group, BaseURL: pending.BaseURL,
		CAPEM: strings.TrimSpace(caPEM), AgentID: pending.ID, AgentPublicKey: pending.PublicKey, Enabled: true,
	}
	seenAt := time.Now().UTC()
	candidate.AgentLastSeenAt = &seenAt
	if pending.ExistingHostID != "" {
		existing, err := h.hosts.Get(pending.ExistingHostID)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		candidate.ID = existing.ID
		candidate.Name = existing.Name
		candidate.Group = existing.Group
		candidate.CreatedAt = existing.CreatedAt
		candidate.Enabled = existing.Enabled
		if candidate.CAPEM == "" {
			candidate.CAPEM = existing.CAPEM
		}
	}
	probeCandidate := *candidate
	probeCandidate.Enabled = true
	if err := h.verifyAgent(ctx, &probeCandidate, pending.AgentKey); err != nil {
		result.Error = err.Error()
		return result
	}
	if pending.ExistingHostID != "" {
		if err := h.hosts.Update(candidate, pending.AgentKey); err != nil {
			result.Error = err.Error()
			return result
		}
	} else if err := h.hosts.Create(candidate, pending.AgentKey); err != nil {
		result.Error = err.Error()
		return result
	}
	saved, err := h.hosts.Get(candidate.ID)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	response := saved.ToResponse()
	result.Success = true
	result.Host = &response
	_ = h.hosts.MarkAgentSeen(pending.ID, seenAt)
	h.mu.Lock()
	delete(h.pending, pending.ID)
	delete(h.rejected, pending.ID)
	h.mu.Unlock()
	return result
}

func (h *EnrollmentHandler) verifyAgent(ctx context.Context, host *model.ManagedHost, key string) error {
	if key == "" {
		return fmt.Errorf("Agent has not supplied a management key")
	}
	resp, err := h.client.Do(ctx, host, key, http.MethodGet, "/api/v1/system/status", "", nil, "")
	if err != nil {
		return fmt.Errorf("Agent verification failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Agent verification returned HTTP %d", resp.StatusCode)
	}
	var envelope APIResponse
	if err := json.Unmarshal(resp.Body, &envelope); err != nil || !envelope.Success {
		return fmt.Errorf("Agent verification returned an invalid response")
	}
	return nil
}

func (h *EnrollmentHandler) reject(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeEnrollmentRequest(w, r)
	if !ok {
		return
	}
	ids := req.IDs
	h.mu.Lock()
	until := time.Now().Add(rejectedEnrollmentTTL)
	for _, id := range ids {
		delete(h.pending, id)
		h.rejected[id] = until
	}
	h.mu.Unlock()
	respondOK(w, map[string]interface{}{"rejected": len(ids), "retry_after": until})
}

func decodeEnrollmentRequest(w http.ResponseWriter, r *http.Request) (enrollmentBatchRequest, bool) {
	var req enrollmentBatchRequest
	if err := decodeJSONBody(w, r, &req, 1024*1024); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return enrollmentBatchRequest{}, false
	}
	if len(req.IDs) == 0 || len(req.IDs) > 100 {
		respondError(w, http.StatusBadRequest, "validation_error", "ids must contain 1-100 pending Agent IDs")
		return enrollmentBatchRequest{}, false
	}
	seen := make(map[string]bool, len(req.IDs))
	for _, id := range req.IDs {
		if !hostIDPattern.MatchString(id) || seen[id] {
			respondError(w, http.StatusBadRequest, "validation_error", "ids contain an invalid or duplicate Agent ID")
			return enrollmentBatchRequest{}, false
		}
		seen[id] = true
	}
	for id, caPEM := range req.CAPEMByID {
		if !seen[id] {
			respondError(w, http.StatusBadRequest, "validation_error", "ca_pem_by_id contains an Agent outside ids")
			return enrollmentBatchRequest{}, false
		}
		if len(caPEM) > 256*1024 {
			respondError(w, http.StatusBadRequest, "validation_error", "CA PEM exceeds 256KB limit")
			return enrollmentBatchRequest{}, false
		}
	}
	return req, true
}

func (h *EnrollmentHandler) uniqueNames(items []*pendingEnrollment) map[string]string {
	used := make(map[string]bool)
	for _, host := range h.hosts.List() {
		used[strings.ToLower(host.Name)] = true
	}
	result := make(map[string]string, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		if item.ExistingHostID != "" {
			if existing, err := h.hosts.Get(item.ExistingHostID); err == nil {
				result[item.ID] = existing.Name
				continue
			}
		}
		name := strings.TrimSpace(item.Name)
		if used[strings.ToLower(name)] {
			suffix := item.ID
			if len(suffix) > 6 {
				suffix = suffix[:6]
			}
			base := []rune(name)
			if len(base) > 57 {
				base = base[:57]
			}
			name = string(base) + "-" + suffix
		}
		used[strings.ToLower(name)] = true
		result[item.ID] = name
	}
	return result
}

func (h *EnrollmentHandler) cleanupLocked(now time.Time) {
	for id, item := range h.pending {
		if now.Sub(item.LastSeenAt) > pendingEnrollmentTTL {
			delete(h.pending, id)
		}
	}
	for id, until := range h.rejected {
		if now.After(until) {
			delete(h.rejected, id)
		}
	}
}
