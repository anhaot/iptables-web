package iptables

import (
	"fmt"
	"testing"

	"iptables-web/internal/model"
)

type recordingBackend struct {
	added         []model.Rule
	deleted       []model.Rule
	legacyDeleted []model.Rule
	deleteErr     error
	exists        bool
}

func (b *recordingBackend) Name() string { return "recording" }

func (b *recordingBackend) AddRule(rule *model.Rule) error {
	cp := *rule
	b.added = append(b.added, cp)
	return nil
}

func (b *recordingBackend) DeleteRule(rule *model.Rule) error {
	cp := *rule
	b.deleted = append(b.deleted, cp)
	return b.deleteErr
}

func TestSyncRulesStopsWhenExistingRuleCannotBeRemoved(t *testing.T) {
	backend := &recordingBackend{deleteErr: fmt.Errorf("remove failed")}
	exe := &Executor{backend: backend}
	rules := []*model.Rule{{ID: "one", Chain: "INPUT", Action: "DROP", Position: 1, Enabled: true}}

	if err := exe.SyncRules(rules); err == nil {
		t.Fatal("SyncRules() succeeded after backend deletion failed")
	}
	if len(backend.added) != 0 {
		t.Fatalf("SyncRules() added %d rules after deletion failure", len(backend.added))
	}
}

func (b *recordingBackend) DeleteLegacyRule(rule *model.Rule) error {
	cp := *rule
	b.legacyDeleted = append(b.legacyDeleted, cp)
	return nil
}

func (b *recordingBackend) RuleExists(rule *model.Rule) (bool, error) { return b.exists, nil }
func (b *recordingBackend) ListRules(chain string) (string, error)    { return "", nil }
func (b *recordingBackend) ListChains() ([]string, error)             { return nil, nil }
func (b *recordingBackend) FlushChain(chain string) error             { return nil }
func (b *recordingBackend) Backup() (string, error)                   { return "", nil }
func (b *recordingBackend) ValidateRestore(data string) error         { return nil }
func (b *recordingBackend) Restore(data string) error                 { return nil }

func TestDeleteRulesUsesMatchingBackends(t *testing.T) {
	packet := &recordingBackend{}
	exe := &Executor{backend: packet, backends: map[string]FirewallBackend{
		model.BackendPacket: packet,
	}}
	rules := []*model.Rule{
		{ID: "packet-1", Backend: model.BackendPacket, Chain: "INPUT"},
	}
	if err := exe.DeleteRules(rules); err != nil {
		t.Fatalf("DeleteRules() error = %v", err)
	}
	if len(packet.deleted) != 1 || packet.deleted[0].ID != "packet-1" {
		t.Fatalf("packet deleted = %#v", packet.deleted)
	}
	if len(packet.legacyDeleted) != 1 || packet.legacyDeleted[0].ID != "packet-1" {
		t.Fatalf("packet legacy deleted = %#v", packet.legacyDeleted)
	}
}

func TestDeleteOwnedRulesNeverDeletesLegacyLookalike(t *testing.T) {
	packet := &recordingBackend{}
	exe := &Executor{backend: packet}
	rules := []*model.Rule{{ID: "agent-owned", Backend: model.BackendPacket, Chain: "INPUT"}}
	if err := exe.DeleteOwnedRules(rules); err != nil {
		t.Fatalf("DeleteOwnedRules() error = %v", err)
	}
	if len(packet.deleted) != 1 {
		t.Fatalf("owned deletions = %d, want 1", len(packet.deleted))
	}
	if len(packet.legacyDeleted) != 0 {
		t.Fatalf("Agent cleanup deleted %d untagged lookalikes", len(packet.legacyDeleted))
	}
}

func TestMigrateLegacyRulesOnlyDeletesUnownedRules(t *testing.T) {
	rule := &model.Rule{ID: "packet-1", Backend: model.BackendPacket, Chain: "INPUT"}
	legacy := &recordingBackend{}
	exe := &Executor{backend: legacy}
	if err := exe.MigrateLegacyRules([]*model.Rule{rule}); err != nil {
		t.Fatalf("MigrateLegacyRules() error = %v", err)
	}
	if len(legacy.legacyDeleted) != 1 {
		t.Fatalf("legacy deletions = %d, want 1", len(legacy.legacyDeleted))
	}

	owned := &recordingBackend{exists: true}
	exe = &Executor{backend: owned}
	if err := exe.MigrateLegacyRules([]*model.Rule{rule}); err != nil {
		t.Fatalf("MigrateLegacyRules() with owned rule error = %v", err)
	}
	if len(owned.legacyDeleted) != 0 {
		t.Fatalf("owned rule triggered %d legacy deletions", len(owned.legacyDeleted))
	}
}

func TestSyncRulesDoesNotDeleteLegacyLookalikes(t *testing.T) {
	backend := &recordingBackend{}
	exe := &Executor{backend: backend}
	rules := []*model.Rule{{ID: "one", Chain: "INPUT", Action: "DROP", Position: 1, Enabled: true}}

	if err := exe.SyncRules(rules); err != nil {
		t.Fatalf("SyncRules() error = %v", err)
	}
	if len(backend.legacyDeleted) != 0 {
		t.Fatalf("SyncRules() deleted %d unowned lookalikes", len(backend.legacyDeleted))
	}
}

func TestSyncRulesDeletesAllAndCompactsEnabledPositions(t *testing.T) {
	backend := &recordingBackend{}
	exe := &Executor{backend: backend}

	rules := []*model.Rule{
		{ID: "disabled-first", Chain: "INPUT", Action: "DROP", Position: 1, Enabled: false},
		{ID: "enabled-second", Chain: "INPUT", Action: "ACCEPT", Position: 2, Enabled: true},
		{ID: "enabled-third", Chain: "INPUT", Action: "DROP", Position: 3, Enabled: true},
	}

	if err := exe.SyncRules(rules); err != nil {
		t.Fatalf("SyncRules() error = %v", err)
	}

	if len(backend.deleted) != 3 {
		t.Fatalf("deleted %d rules, want 3", len(backend.deleted))
	}
	if len(backend.added) != 2 {
		t.Fatalf("added %d rules, want 2", len(backend.added))
	}
	for i, rule := range backend.added {
		wantPosition := i + 1
		if rule.Position != wantPosition {
			t.Fatalf("added[%d].Position = %d, want %d", i, rule.Position, wantPosition)
		}
	}
}

func TestSyncRulesKeepsChainOrderByPosition(t *testing.T) {
	backend := &recordingBackend{}
	exe := &Executor{backend: backend}

	rules := []*model.Rule{
		{ID: "second", Chain: "INPUT", Action: "DROP", Position: 2, Enabled: true},
		{ID: "first", Chain: "INPUT", Action: "ACCEPT", Position: 1, Enabled: true},
	}

	if err := exe.SyncRules(rules); err != nil {
		t.Fatalf("SyncRules() error = %v", err)
	}

	got := fmt.Sprintf("%s,%s", backend.added[0].ID, backend.added[1].ID)
	if got != "first,second" {
		t.Fatalf("added order = %s, want first,second", got)
	}
}
