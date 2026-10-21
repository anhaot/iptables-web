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

func TestToggleCannotEnableDropBeforeMatchingAllow(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	path := filepath.Join(t.TempDir(), "rules.json")
	s := store.NewJSONStore(path)
	for _, rule := range []*model.Rule{
		{ID: "drop", Backend: "packet", Chain: "INPUT", Action: "DROP", Protocol: "tcp", DPort: "8443", Enabled: false, Position: 1},
		{ID: "allow", Backend: "packet", Chain: "INPUT", Action: "ACCEPT", Protocol: "tcp", Source: "192.0.2.10", DPort: "8443", Enabled: true, Position: 2},
	} {
		if err := s.Create(rule); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	NewHandler(s, executor).ToggleRule(rec, httptest.NewRequest("POST", "/api/v1/rules/drop/toggle", nil))
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "unsafe_order") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	reloaded := store.NewJSONStore(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	for _, source := range []*store.JSONStore{s, reloaded} {
		drop, err := source.Get("drop")
		if err != nil || drop.Enabled {
			t.Fatalf("rejected toggle retained in store: %v, %v", drop, err)
		}
	}
}

func TestCreateRejectsSuccessfulCommandWithMissingRuntimeRule(t *testing.T) {
	executor, _ := mockedCleanupExecutor(t, false)
	s := store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	rec := httptest.NewRecorder()
	body := `{"chain":"INPUT","action":"ACCEPT","protocol":"tcp","dport":"8443","enabled":true}`
	NewHandler(s, executor).CreateRule(rec, httptest.NewRequest("POST", "/api/v1/rules", strings.NewReader(body)))
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "is missing") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	rules, err := s.All()
	if err != nil || len(rules) != 0 {
		t.Fatalf("failed verification retained new rule: %v, %v", rules, err)
	}
}
