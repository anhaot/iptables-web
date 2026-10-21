package api

import (
	"encoding/json"
	"iptables-web/internal/iptables"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func batchHandler(t *testing.T) (*Handler, *store.JSONStore) {
	t.Helper()
	t.Setenv("DEV_MODE", "true")
	exe, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	s := store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	return NewHandler(s, exe), s
}

func TestDockerBatchValidatesEntireRequestAndKeepsFallbackLast(t *testing.T) {
	h, s := batchHandler(t)
	mapping := `{"host_port":18080,"container_port":80,"protocol":"tcp","container_name":"web"}`
	bad := `{"sources":["192.0.2.1","bad-address"],"mappings":[` + mapping + `]}`
	rec := httptest.NewRecorder()
	h.CreateDockerWhitelistBatch(rec, httptest.NewRequest("POST", "/api/v1/docker/whitelist/batch", strings.NewReader(bad)))
	rules, _ := s.All()
	if rec.Code != 400 || len(rules) != 0 {
		t.Fatalf("invalid request mutated state: %d %#v", rec.Code, rules)
	}
	body := `{"sources":["192.0.2.1","192.0.2.2","192.0.2.1"],"mappings":[` + mapping + `]}`
	for i := 0; i < 2; i++ {
		rec = httptest.NewRecorder()
		h.CreateDockerWhitelistBatch(rec, httptest.NewRequest("POST", "/api/v1/docker/whitelist/batch", strings.NewReader(body)))
		if rec.Code != 200 {
			t.Fatalf("batch: %d %s", rec.Code, rec.Body.String())
		}
		rules, _ = s.ListByTarget("packet", "DOCKER_USER")
		if len(rules) != 3 || rules[0].Action != "ACCEPT" || rules[1].Action != "ACCEPT" || rules[2].Action != "DROP" {
			t.Fatalf("unsafe or duplicate rules: %#v", rules)
		}
	}
	// An existing ACCEPT with a manually removed fallback must regain protection.
	if _, err := s.Delete(rules[2].ID); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	h.CreateDockerWhitelistBatch(rec, httptest.NewRequest("POST", "/api/v1/docker/whitelist/batch", strings.NewReader(body)))
	rules, _ = s.ListByTarget("packet", "DOCKER_USER")
	if rec.Code != 200 || len(rules) != 3 || rules[2].Action != "DROP" {
		t.Fatal("missing fallback was not repaired")
	}
}

func TestBatchDeleteRejectsStaleOrInvalidSelectionBeforeAnyMutation(t *testing.T) {
	h, s := batchHandler(t)
	for _, id := range []string{"first", "second", "keep"} {
		if err := s.Create(&model.Rule{ID: id, Chain: "INPUT", Action: "ACCEPT", Position: 1, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"rule_ids":["first","missing"]}`, `{"rule_ids":["first","first"]}`, `{"rule_ids":["first"],"expected_updated_at":{"first":"2020-01-01T00:00:00Z"}}`} {
		rec := httptest.NewRecorder()
		h.BatchDeleteRules(rec, httptest.NewRequest("POST", "/api/v1/rules/batch-delete", strings.NewReader(body)))
		if rec.Code != 400 && rec.Code != 409 {
			t.Fatalf("status=%d %s", rec.Code, rec.Body.String())
		}
		rules, _ := s.All()
		if len(rules) != 3 {
			t.Fatal("rejected selection partially deleted rules")
		}
	}
	first, _ := s.Get("first")
	second, _ := s.Get("second")
	body, _ := json.Marshal(map[string]interface{}{"rule_ids": []string{first.ID, second.ID}, "expected_updated_at": map[string]interface{}{first.ID: first.UpdatedAt, second.ID: second.UpdatedAt}})
	rec := httptest.NewRecorder()
	h.BatchDeleteRules(rec, httptest.NewRequest("POST", "/api/v1/rules/batch-delete", strings.NewReader(string(body))))
	rules, _ := s.All()
	if rec.Code != 200 || len(rules) != 1 || rules[0].ID != "keep" {
		t.Fatalf("delete=%d remaining=%#v", rec.Code, rules)
	}
}

func TestBatchPersistenceFailureLeavesFileAndMemoryUnchanged(t *testing.T) {
	h, s := batchHandler(t)
	if err := s.Create(&model.Rule{ID: "keep", Chain: "INPUT", Action: "ACCEPT", Position: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	h.store = &failCleanupSaveStore{Store: s}
	rec := httptest.NewRecorder()
	h.BatchDeleteRules(rec, httptest.NewRequest("POST", "/api/v1/rules/batch-delete", strings.NewReader(`{"rule_ids":["keep"]}`)))
	rules, _ := s.All()
	if rec.Code != 500 || len(rules) != 1 || rules[0].ID != "keep" {
		t.Fatal("persistence failure changed managed rules")
	}
}

func TestBatchKernelFailureRestoresOldOwnedRules(t *testing.T) {
	executor, logPath := mockedCleanupExecutor(t, true)
	dir := filepath.Dir(logPath)
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$CLEANUP_COMMAND_LOG"
case " $* " in
 *" -I INPUT "*) if [ ! -e "$BATCH_FAILED_ONCE" ]; then : > "$BATCH_FAILED_ONCE"; exit 1; fi;;
esac
exit 0
`
	t.Setenv("BATCH_FAILED_ONCE", filepath.Join(dir, "failed"))
	if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rules.json")
	s := store.NewJSONStore(path)
	for _, id := range []string{"remove", "keep"} {
		if err := s.Create(&model.Rule{ID: id, Chain: "INPUT", Action: "ACCEPT", Position: 1, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	NewHandler(s, executor).BatchDeleteRules(rec, httptest.NewRequest("POST", "/api/v1/rules/batch-delete", strings.NewReader(`{"rule_ids":["remove"]}`)))
	rules, _ := s.All()
	loaded := store.NewJSONStore(path)
	err := loaded.Load()
	persisted, _ := loaded.All()
	if rec.Code != 500 || len(rules) != 2 || err != nil || len(persisted) != 2 {
		t.Fatalf("rollback=%d memory=%d disk=%d err=%v", rec.Code, len(rules), len(persisted), err)
	}
	commands, _ := os.ReadFile(logPath)
	if !strings.Contains(string(commands), "--comment iptables-web:remove -j ACCEPT") || strings.Count(string(commands), " -I INPUT ") < 3 {
		t.Fatalf("old rules were not reconstructed: %s", commands)
	}
}
