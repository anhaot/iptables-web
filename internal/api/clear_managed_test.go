package api

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"iptables-web/internal/iptables"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

func TestClearManagedRulesClearsStoreWithDevBackend(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	s := store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	rule := &model.Rule{ID: "managed", Backend: model.BackendPacket, Chain: "INPUT", Action: "ACCEPT", Protocol: "tcp", DPort: "33801", Position: 1, Enabled: true}
	if err := s.Create(rule); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(s, executor)
	recorder := httptest.NewRecorder()
	handler.ClearManagedRules(recorder, httptest.NewRequest("DELETE", "/api/v1/system/managed-rules", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	rules, err := s.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("store still contains %#v", rules)
	}
}
