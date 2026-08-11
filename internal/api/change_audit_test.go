package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"iptables-web/internal/change"
	"iptables-web/internal/iptables"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

func TestChangeAuditMiddlewareRecordsDiffAndRollback(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	dir := t.TempDir()
	rules := store.NewJSONStore(filepath.Join(dir, "rules.json"))
	users := store.NewUserStore(filepath.Join(dir, "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(rules, executor)
	manager := change.NewManager(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "rollback.json"), time.Minute)
	handler.SetChangeManager(manager)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rule := &model.Rule{ID: "new", Backend: model.BackendPacket, Chain: "INPUT", Action: "ACCEPT", Protocol: "tcp", DPort: "33801", Position: 1, Enabled: true}
		if err := rules.Create(rule); err != nil {
			t.Fatal(err)
		}
		if err := rules.Save(); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil)
	ctx := context.WithValue(req.Context(), sessionKey, &store.Session{Username: "admin", Role: "admin"})
	ctx = context.WithValue(ctx, requestIDKey, "request-1")
	req = req.WithContext(ctx)
	recorder := httptest.NewRecorder()
	changeAuditMiddleware(handler, users, nil, nil)(next).ServeHTTP(recorder, req)

	events, err := manager.List(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	if events[0].Action != "create_rule" || events[0].Actor != "admin" || len(events[0].RuleChanges) != 1 {
		t.Fatalf("event=%#v", events[0])
	}
	rollback, err := manager.RollbackStatus()
	if err != nil || rollback == nil || len(rollback.Rules) != 0 {
		t.Fatalf("rollback=%#v err=%v", rollback, err)
	}
}

func TestControllerAuditRequiresAdministratorEvenWithLocalHostGrant(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("AUTH_ENABLED", "true")
	dir := t.TempDir()
	rules := store.NewJSONStore(filepath.Join(dir, "rules.json"))
	if err := rules.Load(); err != nil {
		t.Fatal(err)
	}
	users := store.NewUserStore(filepath.Join(dir, "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	operator := &model.User{ID: "local-operator", Username: "operator", Password: "secret123", Role: "user", HostIDs: []string{model.LocalHostID}, CreatedAt: time.Now()}
	if err := users.Create(operator); err != nil {
		t.Fatal(err)
	}
	if err := users.ChangePassword(operator.ID, "secret123", "Operator234"); err != nil {
		t.Fatal(err)
	}
	login, err := users.Login("operator", "Operator234")
	if err != nil {
		t.Fatal(err)
	}
	hosts := store.NewHostStore(filepath.Join(dir, "hosts.json"), "controller-test-key-at-least-32-characters")
	if err := hosts.Load(); err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeyStore(filepath.Join(dir, "api-keys.json"))
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(rules, executor)
	handler.SetChangeManager(change.NewManager(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "rollback.json"), time.Minute))
	router := NewRouter(
		handler,
		NewAuthHandler(users),
		NewUserHandler(users, hosts),
		NewHostHandler(hosts, users),
		NewEnrollmentHandler(hosts),
		NewAccessKeyHandler(keys),
		users,
		keys,
		os.DirFS("../.."),
	)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/audit", nil)
	req.Header.Set("Authorization", "Bearer "+login.Token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("ordinary local user audit status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRollbackLastChangeRestoresManagedSnapshot(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	dir := t.TempDir()
	rules := store.NewJSONStore(filepath.Join(dir, "rules.json"))
	rule := &model.Rule{ID: "new", Backend: model.BackendPacket, Chain: "INPUT", Action: "ACCEPT", Protocol: "tcp", DPort: "33801", Position: 1, Enabled: true}
	if err := rules.Create(rule); err != nil {
		t.Fatal(err)
	}
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(rules, executor)
	manager := change.NewManager(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "rollback.json"), time.Minute)
	handler.SetChangeManager(manager)
	state, err := manager.SaveRollback("create_rule", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"id":"` + state.ID + `"}`
	recorder := httptest.NewRecorder()
	handler.RollbackLastChange(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/system/rollback", strings.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	remaining, err := rules.All()
	if err != nil || len(remaining) != 0 {
		t.Fatalf("remaining=%#v err=%v", remaining, err)
	}
}

func TestRemoteAndCredentialMutationsDoNotTakeLocalSnapshotLock(t *testing.T) {
	for _, path := range []string{
		"/api/v1/hosts",
		"/api/v1/hosts/00112233445566778899aabb/api/rules",
		"/api/v1/hosts/batch/rules",
		"/api/v1/agent-enrollments/approve",
		"/api/v1/access-keys",
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if mutationChangesLocalSnapshot(req) {
			t.Fatalf("%s should not take the local rule/user snapshot lock", path)
		}
	}
	for _, path := range []string{"/api/v1/rules", "/api/v1/users", "/api/v1/security-policy", "/api/v1/system/restore"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if !mutationChangesLocalSnapshot(req) {
			t.Fatalf("%s must retain the local rule/user snapshot lock", path)
		}
	}
	policyReq := httptest.NewRequest(http.MethodPut, "/api/v1/security-policy", nil)
	if got := auditAction(policyReq); got != "update_security_policy" {
		t.Fatalf("security-policy audit action = %q", got)
	}
	enrollmentReq := httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollments/approve", nil)
	if !isMutationRequest(enrollmentReq) || auditAction(enrollmentReq) != "approve_agent_enrollment" {
		t.Fatalf("Agent enrollment approval was not classified for audit")
	}
	heartbeatReq := httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollments/register", nil)
	if isMutationRequest(heartbeatReq) {
		t.Fatal("periodic Agent registration/heartbeat must not flood the change audit")
	}
}
