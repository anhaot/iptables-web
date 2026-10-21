package api

import (
	"crypto/sha256"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"iptables-web/internal/iptables"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

func mockedCleanupExecutor(t *testing.T, ownedExists bool) (*iptables.Executor, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("DEV_MODE", "false")
	t.Setenv("FIREWALL_BACKEND", "iptables")
	t.Setenv("CLEANUP_COMMAND_LOG", logPath)
	t.Setenv("OWNED_EXISTS", fmt.Sprint(ownedExists))
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$CLEANUP_COMMAND_LOG"
case " $* " in
 *" -C "*) case " $* " in
   *" --comment "*) [ "$OWNED_EXISTS" = true ];;
   *) exit 0;;
 esac;;
 *) exit 0;;
esac
`
	for _, name := range []string{"iptables", "iptables-save", "iptables-restore"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	return executor, logPath
}

func TestAgentClearPreservesUntaggedLookalike(t *testing.T) {
	executor, logPath := mockedCleanupExecutor(t, false)
	s := store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := s.Create(&model.Rule{ID: "disabled", Backend: "packet", Chain: "INPUT", Action: "DROP", Protocol: "tcp", DPort: "8443", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("test-agent-key"))
	router := NewAgentRouter(NewHandler(s, executor), hash[:])
	req := httptest.NewRequest("DELETE", "/api/v1/system/managed-rules", nil)
	req.Header.Set("X-API-Key", "test-agent-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	commands, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(commands), " -D ") {
		t.Fatalf("deleted an external lookalike: %s", commands)
	}
}

type failCleanupSaveStore struct{ store.Store }

func (s *failCleanupSaveStore) Save() error { return fmt.Errorf("simulated disk failure") }

func TestClearRestoresRuntimeAfterPersistenceFailure(t *testing.T) {
	executor, logPath := mockedCleanupExecutor(t, true)
	s := store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	if err := s.Create(&model.Rule{ID: "owned", Backend: "packet", Chain: "INPUT", Action: "DROP", Protocol: "tcp", DPort: "8443", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(&failCleanupSaveStore{Store: s}, executor)
	rec := httptest.NewRecorder()
	h.ClearManagedRules(rec, httptest.NewRequest("DELETE", "/api/v1/system/managed-rules", nil))
	if rec.Code != 500 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	rules, err := s.All()
	if err != nil || len(rules) != 1 || rules[0].ID != "owned" {
		t.Fatalf("memory was not restored: rules=%v error=%v", rules, err)
	}
	commands, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(commands), "-I INPUT 1") {
		t.Fatalf("runtime was not restored after deleting rules: %s", commands)
	}
}

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
