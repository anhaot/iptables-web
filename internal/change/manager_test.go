package change

import (
	"path/filepath"
	"testing"
	"time"

	"iptables-web/internal/model"
)

func TestAuditAndRollbackPersistence(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "rollback.json"), time.Minute)
	event := AuditEvent{Actor: "admin", Method: "POST", Path: "/api/v1/rules", Action: "create_rule", Status: 201}
	if err := manager.Record(event); err != nil {
		t.Fatal(err)
	}
	events, err := manager.List(10)
	if err != nil || len(events) != 1 || events[0].Actor != "admin" {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	rules := []*model.Rule{{ID: "one", Chain: "INPUT", Action: "ACCEPT", Position: 1, Enabled: true}}
	if _, err := manager.SaveRollback("create_rule", "admin", rules); err != nil {
		t.Fatal(err)
	}
	state, err := manager.RollbackStatus()
	if err != nil || state == nil || len(state.Rules) != 1 || state.Rules[0].ID != "one" {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	state.Rules[0].ID = "changed"
	reloaded, _ := manager.RollbackStatus()
	if reloaded.Rules[0].ID != "one" {
		t.Fatal("rollback status leaked internal rule pointer")
	}
}

func TestDiffRulesAndUsers(t *testing.T) {
	beforeRules := []*model.Rule{{ID: "one", Chain: "INPUT", Action: "ACCEPT", Position: 1}}
	afterRules := []*model.Rule{{ID: "one", Chain: "INPUT", Action: "DROP", Position: 1}, {ID: "two", Chain: "OUTPUT", Action: "ACCEPT", Position: 1}}
	changes := DiffRules(beforeRules, afterRules)
	if len(changes) != 2 || changes[0].Before.Action != "ACCEPT" || changes[0].After.Action != "DROP" || changes[1].Before != nil {
		t.Fatalf("changes=%#v", changes)
	}
	beforeUsers := []model.UserResponse{{ID: "u1", Username: "admin", Role: "admin"}}
	afterUsers := []model.UserResponse{{ID: "u1", Username: "admin", Role: "user"}}
	userChanges := DiffUsers(beforeUsers, afterUsers)
	if len(userChanges) != 1 || userChanges[0].After.Role != "user" {
		t.Fatalf("user changes=%#v", userChanges)
	}
}
