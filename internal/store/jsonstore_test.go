package store

import (
	"os"
	"path/filepath"
	"testing"

	"iptables-web/internal/model"
)

func TestJSONStoreMaintainsRulePositions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "rules.json")
	s := NewJSONStore(path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	first := &model.Rule{ID: "first", Chain: "INPUT", Action: "DROP", Protocol: "tcp", DPort: "80"}
	second := &model.Rule{ID: "second", Chain: "INPUT", Action: "ACCEPT", Protocol: "tcp", DPort: "443"}
	inserted := &model.Rule{ID: "inserted", Chain: "INPUT", Action: "REJECT", Protocol: "tcp", DPort: "8080", Position: 1}

	if err := s.Create(first); err != nil {
		t.Fatalf("Create(first) error = %v", err)
	}
	if err := s.Create(second); err != nil {
		t.Fatalf("Create(second) error = %v", err)
	}
	if err := s.Create(inserted); err != nil {
		t.Fatalf("Create(inserted) error = %v", err)
	}

	assertOrder(t, s, []string{"inserted", "first", "second"})

	if _, err := s.Delete("first"); err != nil {
		t.Fatalf("Delete(first) error = %v", err)
	}
	assertOrder(t, s, []string{"inserted", "second"})

	if err := s.Reorder("INPUT", []string{"second", "inserted"}); err != nil {
		t.Fatalf("Reorder() error = %v", err)
	}
	assertOrder(t, s, []string{"second", "inserted"})

	if err := s.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("rules file was not created: %v", err)
	}
}

func TestJSONStoreRejectsPartialReorder(t *testing.T) {
	t.Parallel()

	s := NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := s.Create(&model.Rule{ID: "one", Chain: "FORWARD", Action: "DROP", Position: 1}); err != nil {
		t.Fatalf("Create(one) error = %v", err)
	}
	if err := s.Create(&model.Rule{ID: "two", Chain: "FORWARD", Action: "DROP", Position: 2}); err != nil {
		t.Fatalf("Create(two) error = %v", err)
	}

	if err := s.Reorder("FORWARD", []string{"two"}); err == nil {
		t.Fatal("Reorder() with a partial id list succeeded, want error")
	}
}

func TestJSONStoreReturnsClonedRules(t *testing.T) {
	s := NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := s.Create(&model.Rule{ID: "one", Chain: "INPUT", Action: "DROP", Position: 1}); err != nil {
		t.Fatal(err)
	}
	rule, err := s.Get("one")
	if err != nil {
		t.Fatal(err)
	}
	rule.Action = "ACCEPT"
	again, _ := s.Get("one")
	if again.Action != "DROP" {
		t.Fatalf("mutating Get result changed store: %#v", again)
	}
}

func assertOrder(t *testing.T, s *JSONStore, want []string) {
	t.Helper()

	rules, err := s.List("INPUT")
	if err != nil {
		t.Fatalf("List(INPUT) error = %v", err)
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d", len(rules), len(want))
	}
	for i, id := range want {
		if rules[i].ID != id {
			t.Fatalf("rule[%d] = %s, want %s", i, rules[i].ID, id)
		}
		if rules[i].Position != i+1 {
			t.Fatalf("rule[%d].Position = %d, want %d", i, rules[i].Position, i+1)
		}
	}
}

func TestJSONStoreLoadRejectsInvalidRulesWithoutReplacingMemory(t *testing.T) {
	for name, data := range map[string]string{
		"null entry":      `[null]`,
		"empty id":        `[{"chain":"INPUT","action":"ACCEPT"}]`,
		"duplicate id":    `[{"id":"dup","chain":"INPUT","action":"ACCEPT"},{"id":"dup","chain":"OUTPUT","action":"DROP"}]`,
		"invalid action":  `[{"id":"bad","chain":"INPUT","action":"EXEC"}]`,
		"invalid address": `[{"id":"bad","chain":"INPUT","action":"ACCEPT","source":"::1"}]`,
		"invalid json":    `[{"id":"bad"`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.json")
			s := NewJSONStore(path)
			if err := s.Create(&model.Rule{ID: "original", Chain: "INPUT", Action: "ACCEPT"}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := s.Load(); err == nil {
				t.Fatal("invalid rules file was accepted")
			}
			rules, err := s.All()
			if err != nil || len(rules) != 1 || rules[0].ID != "original" {
				t.Fatalf("failed Load replaced memory: %#v, %v", rules, err)
			}
		})
	}
}

func TestJSONStoreLoadsLegacyPositionsAndBackend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`[{"id":"legacy","backend":"iptables","chain":"input","action":"accept"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewJSONStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	rule, err := s.Get("legacy")
	if err != nil || rule.Position != 1 || rule.Backend != model.BackendPacket || rule.Chain != "INPUT" {
		t.Fatalf("legacy normalization: %#v, %v", rule, err)
	}
}

func TestJSONStoreRetainsLegacyMetadataForStartupMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	data := `[{"id":"firewalld","backend":"firewalld","chain":"INPUT"},{"id":"docker","chain":"DOCKER_USER","action":"ACCEPT","protocol":"tcp","dport":"8080","original_dport":"8080"}]`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewJSONStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	legacy, _ := s.Get("firewalld")
	docker, _ := s.Get("docker")
	if legacy.Backend != "firewalld" || docker.DPort != "8080" || docker.OriginalDPort != "8080" {
		t.Fatal("Load bypassed or broke the explicit startup migrations")
	}
}
