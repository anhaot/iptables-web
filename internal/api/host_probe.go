package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
	"net/http"
	"time"
)

type hostProbe struct {
	config    [32]byte
	done      chan struct{}
	checkedAt time.Time
	status    int
	code      string
	message   string
	data      map[string]interface{}
}

func (h *HostHandler) SetMonitoringStore(s *store.MonitoringStore) { h.monitoring = s }

// A single cache shared by all controller users coalesces concurrent probes.
// Keys include the verified endpoint/CA/credential so edits take effect at once.
func (h *HostHandler) probeHost(w http.ResponseWriter, r *http.Request, id string) {
	host, key, err := h.store.GetWithAPIKey(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	if !host.Enabled {
		respondError(w, http.StatusConflict, "host_disabled", "主机已停用")
		return
	}
	config := sha256.Sum256([]byte(host.BaseURL + "\x00" + host.CAPEM + "\x00" + host.APIKeyCipher))
	interval := time.Duration(h.monitoring.Get().ForHost(host).ProbeIntervalSeconds) * time.Second
	force := r.URL.Query().Get("force") == "1"
	for {
		h.probeMu.Lock()
		if cached := h.probes[id]; cached != nil && cached.config == config {
			if cached.done != nil {
				done := cached.done
				h.probeMu.Unlock()
				select {
				case <-done:
					force = false
					continue
				case <-r.Context().Done():
					return
				}
			}
			if !force && time.Since(cached.checkedAt) < interval {
				result := *cached
				h.probeMu.Unlock()
				writeHostProbe(w, result)
				return
			}
		}
		probe := &hostProbe{config: config, done: make(chan struct{})}
		if h.probes == nil {
			h.probes = make(map[string]*hostProbe)
		}
		h.probes[id] = probe
		h.probeMu.Unlock()
		result := h.runHostProbe(r, host, key)
		h.probeMu.Lock()
		probe.checkedAt = result.checkedAt
		probe.status = result.status
		probe.code = result.code
		probe.message = result.message
		probe.data = result.data
		close(probe.done)
		probe.done = nil
		if r.Context().Err() != nil && h.probes[id] == probe {
			delete(h.probes, id)
		}
		h.probeMu.Unlock()
		writeHostProbe(w, result)
		return
	}
}

func (h *HostHandler) runHostProbe(r *http.Request, host *model.ManagedHost, key string) hostProbe {
	started := time.Now()
	result := hostProbe{status: http.StatusBadGateway, checkedAt: started.UTC()}
	resp, err := h.client.Do(r.Context(), host, key, http.MethodGet, "/api/v1/system/status", "", nil, "")
	result.checkedAt = time.Now().UTC()
	if err != nil {
		result.code = "remote_unreachable"
		result.message = err.Error()
		return result
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.code = "remote_unhealthy"
		result.message = fmt.Sprintf("remote authentication/status check returned HTTP %d", resp.StatusCode)
		return result
	}
	var health APIResponse
	if err := json.Unmarshal(resp.Body, &health); err != nil || !health.Success {
		result.code = "remote_invalid_response"
		result.message = "remote status response is invalid"
		return result
	}
	result.status = http.StatusOK
	result.data = map[string]interface{}{"online": true, "latency_ms": time.Since(started).Milliseconds(), "health": health.Data, "checked_at": result.checkedAt}
	return result
}

func writeHostProbe(w http.ResponseWriter, result hostProbe) {
	if result.status != http.StatusOK {
		respondError(w, result.status, result.code, result.message)
		return
	}
	respondOK(w, result.data)
}
