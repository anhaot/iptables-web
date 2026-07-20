package api

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"iptables-web/internal/iptables"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

func TestValidateRuleOrderRejectsSourcelessDropBeforeAllow(t *testing.T) {
	t.Parallel()

	s := store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	allow := &model.Rule{ID: "allow", Chain: "INPUT", Action: "ACCEPT", Protocol: "tcp", Source: "10.11.24.54", DPort: "10089", Position: 1, Enabled: true}
	drop := &model.Rule{ID: "drop", Chain: "INPUT", Action: "DROP", Protocol: "tcp", DPort: "10089", Position: 2, Enabled: true}
	if err := s.Create(allow); err != nil {
		t.Fatalf("Create(allow) error = %v", err)
	}
	if err := s.Create(drop); err != nil {
		t.Fatalf("Create(drop) error = %v", err)
	}

	h := &Handler{store: s}
	if err := h.validateRuleOrder(model.BackendPacket, "INPUT", []string{"drop", "allow"}); err == nil {
		t.Fatal("validateRuleOrder accepted DROP before matching ACCEPT, want error")
	}
}

func TestCreateRuleRejectsUnsafePosition(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	s := store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	allow := &model.Rule{ID: "allow", Backend: model.BackendPacket, Chain: "INPUT", Action: "ACCEPT", Protocol: "tcp", Source: "10.11.24.54", DPort: "10089", Position: 1, Enabled: true}
	if err := s.Create(allow); err != nil {
		t.Fatal(err)
	}
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(s, executor)
	recorder := httptest.NewRecorder()
	body := `{"chain":"INPUT","action":"DROP","protocol":"tcp","dport":"10089","position":1,"enabled":true}`
	h.CreateRule(recorder, httptest.NewRequest("POST", "/api/v1/rules", strings.NewReader(body)))
	if recorder.Code != 400 || !strings.Contains(recorder.Body.String(), "unsafe_order") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	rules, _ := s.ListByTarget(model.BackendPacket, "INPUT")
	if len(rules) != 1 || rules[0].ID != "allow" {
		t.Fatalf("unsafe rule was retained: %#v", rules)
	}
}

func TestValidateRuleOrderAllowsDropAfterAllow(t *testing.T) {
	t.Parallel()

	s := store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	allow := &model.Rule{ID: "allow", Chain: "INPUT", Action: "ACCEPT", Protocol: "tcp", Source: "10.11.24.54", DPort: "10089", Position: 1, Enabled: true}
	drop := &model.Rule{ID: "drop", Chain: "INPUT", Action: "DROP", Protocol: "tcp", DPort: "10089", Position: 2, Enabled: true}
	if err := s.Create(allow); err != nil {
		t.Fatalf("Create(allow) error = %v", err)
	}
	if err := s.Create(drop); err != nil {
		t.Fatalf("Create(drop) error = %v", err)
	}

	h := &Handler{store: s}
	if err := h.validateRuleOrder(model.BackendPacket, "INPUT", []string{"allow", "drop"}); err != nil {
		t.Fatalf("validateRuleOrder returned error = %v", err)
	}
}
