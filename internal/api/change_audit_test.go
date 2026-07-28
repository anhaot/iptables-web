package api

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	changeAuditMiddleware(handler, users)(next).ServeHTTP(recorder, req)

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
