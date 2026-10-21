package api

import (
	"context"
	"iptables-web/internal/change"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMonitoringPolicyIsReadableButOnlyAdminsCanChange(t *testing.T) {
	h := NewHostHandler(nil)
	audit := change.NewManager(filepath.Join(t.TempDir(), "audit.jsonl"), "", time.Minute)
	body := `{"probe_interval_seconds":120,"offline_after_seconds":90}`
	for _, role := range []string{"user", "admin"} {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/monitoring-policy", strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), sessionKey, &store.Session{Username: role, Role: role}))
		rec := httptest.NewRecorder()
		h.monitoringPolicy(rec, req, audit)
		want := 403
		if role == "admin" {
			want = 200
		}
		if rec.Code != want {
			t.Fatalf("%s status=%d body=%s", role, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h.monitoringPolicy(rec, httptest.NewRequest("GET", "/api/v1/monitoring-policy", nil), audit)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"probe_interval_seconds":120`) {
		t.Fatal(rec.Body.String())
	}
	events, err := audit.List(10)
	if err != nil || len(events) != 1 || events[0].MonitoringPolicyBefore.ProbeIntervalSeconds != 60 {
		t.Fatalf("audit=%v err=%v", events, err)
	}
}

func TestHostProbeCacheSharesResultsAndSupportsForceAndConfigurationChanges(t *testing.T) {
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(30 * time.Millisecond)
		w.Write([]byte(`{"success":true,"data":{"ok":true}}`))
	}))
	defer remote.Close()
	hosts := store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "test-master-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "host", Name: "node", BaseURL: remote.URL, Enabled: true}
	if err := hosts.Create(host, "test-key"); err != nil {
		t.Fatal(err)
	}
	h := NewHostHandler(hosts)
	probe := func(force bool) {
		url := "/api/v1/hosts/host/probe"
		if force {
			url += "?force=1"
		}
		rec := httptest.NewRecorder()
		h.probeHost(rec, httptest.NewRequest("GET", url, nil), host.ID)
		if rec.Code != 200 {
			t.Errorf("probe=%d %s", rec.Code, rec.Body.String())
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); probe(false) }()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent requests made %d probes", calls.Load())
	}
	probe(false)
	if calls.Load() != 1 {
		t.Fatal("cached request re-probed")
	}
	probe(true)
	if calls.Load() != 2 {
		t.Fatal("forced probe did not bypass cache")
	}
	if err := hosts.Update(host, "rotated-key"); err != nil {
		t.Fatal(err)
	}
	probe(false)
	if calls.Load() != 3 {
		t.Fatal("new credential reused old probe")
	}
	h.probeMu.Lock()
	h.probes[host.ID].checkedAt = time.Now().Add(-31 * time.Second)
	h.probeMu.Unlock()
	if err := h.monitoring.Update(model.MonitoringPolicy{ProbeIntervalSeconds: 120, OfflineAfterSeconds: 45}); err != nil {
		t.Fatal(err)
	}
	probe(false)
	if calls.Load() != 3 {
		t.Fatal("global interval ignored")
	}
	host.ProbeIntervalSeconds = 30
	if err := hosts.Update(host, ""); err != nil {
		t.Fatal(err)
	}
	probe(false)
	if calls.Load() != 4 {
		t.Fatal("host interval override ignored")
	}
}

func TestHostMonitoringOverridesPersistAndRejectInvalidValues(t *testing.T) {
	hosts := store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "test-master-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node", BaseURL: "http://192.0.2.1:33802", Enabled: true}
	if err := hosts.Create(host, "test-key"); err != nil {
		t.Fatal(err)
	}
	h := NewHostHandler(hosts)
	for _, test := range []struct {
		body   string
		status int
	}{
		{`{"name":"node","probe_interval_seconds":120,"offline_after_seconds":90,"enabled":true}`, 200},
		{`{"name":"renamed","enabled":true}`, 200},
		{`{"name":"node","probe_interval_seconds":3,"enabled":true}`, 400},
	} {
		req := httptest.NewRequest("PUT", "/api/v1/hosts/"+host.ID, strings.NewReader(test.body))
		rec := httptest.NewRecorder()
		h.updateHost(rec, req)
		if rec.Code != test.status {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
	got, _ := hosts.Get(host.ID)
	if got.ProbeIntervalSeconds != 120 || got.OfflineAfterSeconds != 90 {
		t.Fatalf("override lost: %+v", got)
	}
	rec := httptest.NewRecorder()
	h.updateHost(rec, httptest.NewRequest("PUT", "/api/v1/hosts/"+host.ID, strings.NewReader(`{"name":"node","probe_interval_seconds":0,"offline_after_seconds":0,"enabled":true}`)))
	got, _ = hosts.Get(host.ID)
	if rec.Code != 200 || got.ProbeIntervalSeconds != 0 || got.OfflineAfterSeconds != 0 {
		t.Fatal("could not restore inheritance")
	}
}
