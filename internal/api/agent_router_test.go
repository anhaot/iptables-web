package api

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"iptables-web/internal/change"
	"iptables-web/internal/iptables"
	"iptables-web/internal/store"
)

func TestAgentRouterRequiresKeyExceptForHealth(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	key := "ipwa_test-agent-key"
	hash := sha256.Sum256([]byte(key))
	rules := store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := rules.Load(); err != nil {
		t.Fatal(err)
	}
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	router := NewAgentRouter(NewHandler(rules, executor), hash[:])

	health := httptest.NewRecorder()
	router.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("public health status=%d body=%s", health.Code, health.Body.String())
	}

	unauthorized := httptest.NewRecorder()
	router.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("missing-key status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}
	if unauthorized.Header().Get("X-Request-ID") == "" || unauthorized.Header().Get("X-Content-Type-Options") != "nosniff" || unauthorized.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("missing-key response is missing common security headers: %#v", unauthorized.Header())
	}

	authorizedReq := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	authorizedReq.Header.Set("X-API-Key", key)
	authorized := httptest.NewRecorder()
	router.ServeHTTP(authorized, authorizedReq)
	if authorized.Code != http.StatusOK || !strings.Contains(authorized.Body.String(), `"data":[]`) {
		t.Fatalf("valid-key status=%d body=%s", authorized.Code, authorized.Body.String())
	}
}

func TestAgentAuditUsesControllerForwardedIdentity(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	key := "ipwa_test-agent-key"
	hash := sha256.Sum256([]byte(key))
	dir := t.TempDir()
	rules := store.NewJSONStore(filepath.Join(dir, "rules.json"))
	if err := rules.Load(); err != nil {
		t.Fatal(err)
	}
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(rules, executor)
	manager := change.NewManager(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "rollback.json"), time.Minute)
	handler.SetChangeManager(manager)
	router := NewAgentRouter(handler, hash[:])

	body := bytes.NewBufferString(`{"backend":"packet","chain":"INPUT","action":"ACCEPT","protocol":"tcp","dport":"22","position":1,"enabled":true,"desc":"SSH"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-Iptables-Web-Audit-Actor-B64", "YWRtaW4")
	req.Header.Set("X-Iptables-Web-Audit-Role", "admin")
	req.Header.Set("X-Iptables-Web-Audit-Remote-IP", "192.0.2.25")
	req.Header.Set("X-Request-ID", "controller-request-1")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	events, err := manager.List(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	event := events[0]
	if event.Actor != "admin" || event.Role != "admin" || event.RemoteIP != "192.0.2.25" || event.RequestID != "controller-request-1" || len(event.RuleChanges) != 1 {
		t.Fatalf("forwarded audit event=%#v", event)
	}
}

func TestAgentRouterDoesNotExposeControllerAPIs(t *testing.T) {
	hash := sha256.Sum256([]byte("ipwa_test-agent-key"))
	router := NewAgentRouter(NewHandler(store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json")), nil), hash[:])
	for _, path := range []string{
		"/api/v1/users",
		"/api/v1/auth/session",
		"/api/v1/hosts",
		"/api/v1/access-keys",
		"/api/v1/assistant/generate",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-API-Key", "ipwa_test-agent-key")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("controller route %s exposed with status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestAgentKeyVerifierRotatesWithoutRouterRestart(t *testing.T) {
	oldKey := "ipwa_old-key"
	newKey := "ipwa_new-key"
	oldHash := sha256.Sum256([]byte(oldKey))
	newHash := sha256.Sum256([]byte(newKey))
	verifier := NewAgentKeyVerifier(oldHash[:])
	if !verifier.Valid(oldKey) || verifier.Valid(newKey) {
		t.Fatal("unexpected verifier state before rotation")
	}
	verifier.Update(newHash[:])
	if verifier.Valid(oldKey) || !verifier.Valid(newKey) {
		t.Fatal("verifier did not apply rotated key immediately")
	}
}
