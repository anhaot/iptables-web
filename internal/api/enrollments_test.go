package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"iptables-web/internal/enrollment"
	"iptables-web/internal/store"
)

func TestAgentEnrollmentRequiresApprovalAndNeverListsKey(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	agentKey := "ipwa_test-enrollment-secret"
	agent := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/system/status" || r.Header.Get("X-API-Key") != agentKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"firewall_backend":"dev"}}`))
	}))
	agent.Listener = listener
	agent.Start()
	defer agent.Close()

	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts.json")
	hosts := store.NewHostStore(hostsPath, "controller-test-key-at-least-32-characters")
	if err := hosts.Load(); err != nil {
		t.Fatal(err)
	}
	handler := NewEnrollmentHandler(hosts)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	reqBody, err := enrollment.NewSignedRequest(privateKey, "node-a", "prod", agent.URL, agentKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(reqBody)
	register := httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollments/register", bytes.NewReader(body))
	register.RemoteAddr = "127.0.0.1:43210"
	registered := httptest.NewRecorder()
	handler.ServeHTTP(registered, register)
	if registered.Code != http.StatusOK || !strings.Contains(registered.Body.String(), `"status":"pending"`) {
		t.Fatalf("register status=%d body=%s", registered.Code, registered.Body.String())
	}
	if len(hosts.List()) != 0 {
		t.Fatal("Agent became managed before administrator approval")
	}

	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, httptest.NewRequest(http.MethodGet, "/api/v1/agent-enrollments", nil))
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), reqBody.AgentID) {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	if strings.Contains(listed.Body.String(), agentKey) || strings.Contains(listed.Body.String(), reqBody.PublicKey) {
		t.Fatalf("pending list exposed enrollment credentials: %s", listed.Body.String())
	}

	approveBody := bytes.NewBufferString(`{"ids":["` + reqBody.AgentID + `"]}`)
	approved := httptest.NewRecorder()
	handler.ServeHTTP(approved, httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollments/approve", approveBody))
	if approved.Code != http.StatusOK || !strings.Contains(approved.Body.String(), `"success":true`) {
		t.Fatalf("approve status=%d body=%s", approved.Code, approved.Body.String())
	}
	managed, err := hosts.GetByAgentID(reqBody.AgentID)
	if err != nil || managed.Name != "node-a" {
		t.Fatalf("managed host=%#v err=%v", managed, err)
	}
	if managed.AgentLastSeenAt == nil || time.Since(*managed.AgentLastSeenAt) > time.Minute {
		t.Fatalf("managed Agent heartbeat was not recorded: %#v", managed.AgentLastSeenAt)
	}

	// A subsequently signed registration is the Agent heartbeat. It refreshes
	// liveness without adding another pending enrollment or exposing its key.
	time.Sleep(2 * time.Millisecond)
	heartbeatBody, err := enrollment.NewSignedRequest(privateKey, "node-a", "prod", agent.URL, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	heartbeatJSON, _ := json.Marshal(heartbeatBody)
	heartbeat := httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollments/register", bytes.NewReader(heartbeatJSON))
	heartbeat.RemoteAddr = "127.0.0.1:43211"
	heartbeatResponse := httptest.NewRecorder()
	handler.ServeHTTP(heartbeatResponse, heartbeat)
	if heartbeatResponse.Code != http.StatusOK || !strings.Contains(heartbeatResponse.Body.String(), `"status":"approved"`) {
		t.Fatalf("heartbeat status=%d body=%s", heartbeatResponse.Code, heartbeatResponse.Body.String())
	}
	refreshed, err := hosts.GetByAgentID(reqBody.AgentID)
	if err != nil || refreshed.AgentLastSeenAt == nil || !refreshed.AgentLastSeenAt.After(*managed.AgentLastSeenAt) {
		t.Fatalf("Agent heartbeat was not refreshed: before=%v after=%#v err=%v", managed.AgentLastSeenAt, refreshed.AgentLastSeenAt, err)
	}
	persisted, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(persisted, []byte(agentKey)) {
		t.Fatal("Agent key was persisted in plaintext")
	}
}

func TestHTTPSAgentEnrollmentAcceptsCAAndReusesItForKeyRotation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	var expectedKey atomic.Value
	expectedKey.Store("ipwa_initial-secret")
	agent := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/system/status" || r.Header.Get("X-API-Key") != expectedKey.Load().(string) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"firewall_backend":"dev"}}`))
	}))
	agent.Listener = listener
	agent.StartTLS()
	defer agent.Close()

	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agent.Certificate().Raw}))
	hosts := store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
	if err := hosts.Load(); err != nil {
		t.Fatal(err)
	}
	handler := NewEnrollmentHandler(hosts)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	registerAgent := func(agentKey string) enrollment.Request {
		reqBody, err := enrollment.NewSignedRequest(privateKey, "secure-node", "prod", agent.URL, agentKey, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollments/register", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:43210"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("register status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		return reqBody
	}

	first := registerAgent(expectedKey.Load().(string))
	approveJSON, _ := json.Marshal(enrollmentBatchRequest{
		IDs: []string{first.AgentID}, CAPEMByID: map[string]string{first.AgentID: caPEM},
	})
	approved := httptest.NewRecorder()
	handler.ServeHTTP(approved, httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollments/approve", bytes.NewReader(approveJSON)))
	if approved.Code != http.StatusOK || !strings.Contains(approved.Body.String(), `"success":true`) {
		t.Fatalf("approve status=%d body=%s", approved.Code, approved.Body.String())
	}
	managed, err := hosts.GetByAgentID(first.AgentID)
	if err != nil || managed.CAPEM != strings.TrimSpace(caPEM) {
		t.Fatalf("custom CA was not persisted: host=%#v err=%v", managed, err)
	}

	expectedKey.Store("ipwa_rotated-secret")
	rotated := registerAgent(expectedKey.Load().(string))
	if rotated.AgentID != first.AgentID {
		t.Fatalf("Agent identity changed during key rotation")
	}
	_, storedKey, err := hosts.GetWithAPIKey(managed.ID)
	if err != nil || storedKey != expectedKey.Load().(string) {
		t.Fatalf("rotated key was not saved: key=%q err=%v", storedKey, err)
	}
	managed, err = hosts.Get(managed.ID)
	if err != nil || managed.CAPEM != strings.TrimSpace(caPEM) {
		t.Fatalf("key rotation discarded custom CA: host=%#v err=%v", managed, err)
	}
}

func TestEnrollmentURLIsPinnedToRequestSourceIP(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:33802", "http://agent.internal:33802"} {
		got, err := enrollmentURLForSource(target, "192.0.2.25")
		if err != nil || got != "http://192.0.2.25:33802" {
			t.Fatalf("bound URL for %q = %q, err=%v", target, got, err)
		}
	}
	if _, err := enrollmentURLForSource("http://127.0.0.1:33802", "not-an-ip"); err == nil {
		t.Fatal("non-IP request source was accepted")
	}
}

func TestAgentEnrollmentRejectsTamperedRequest(t *testing.T) {
	hosts := store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
	if err := hosts.Load(); err != nil {
		t.Fatal(err)
	}
	handler := NewEnrollmentHandler(hosts)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	reqBody, _ := enrollment.NewSignedRequest(privateKey, "node-a", "", "http://192.0.2.10:33802", "ipwa_secret", time.Now())
	reqBody.Name = "spoofed"
	body, _ := json.Marshal(reqBody)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollments/register", bytes.NewReader(body)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("tampered status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
