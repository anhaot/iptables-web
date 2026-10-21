package api

import (
	"encoding/json"
	"iptables-web/internal/iptables"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

func TestFailedRestoreAttemptsPreviousPacketBackup(t *testing.T) {
	executor, logPath := mockedCleanupExecutor(t, true)
	dir := filepath.Dir(logPath)
	previous := "*filter\n-P INPUT ACCEPT\nCOMMIT\n"
	if err := os.WriteFile(filepath.Join(dir, "iptables-save"), []byte("#!/bin/sh\nprintf '*filter\\n-P INPUT ACCEPT\\nCOMMIT\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RESTORE_ATTEMPTED", filepath.Join(dir, "attempted"))
	script := `#!/bin/sh
data=$(cat)
case " $* " in *" --test "*) exit 0;; esac
printf '%s\n' "$data" >> "$CLEANUP_COMMAND_LOG"
if [ ! -e "$RESTORE_ATTEMPTED" ]; then
 : > "$RESTORE_ATTEMPTED"
 exit 1
fi
`
	if err := os.WriteFile(filepath.Join(dir, "iptables-restore"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	newDump := "*filter\n-P INPUT DROP\nCOMMIT\n"
	body, err := json.Marshal(map[string]string{"data": newDump})
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(store.NewJSONStore(filepath.Join(dir, "rules.json")), executor)
	rec := httptest.NewRecorder()
	h.RestoreRules(rec, httptest.NewRequest("POST", "/api/v1/system/restore", strings.NewReader(string(body))))
	if rec.Code != 500 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	commands, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(commands), previous) {
		t.Fatalf("failure did not attempt the previous packet backup: %s", commands)
	}
}

func TestBuildCombinedBackupIncludesExpectedFiles(t *testing.T) {
	manifest := combinedBackupManifest{Format: "iptables-web-combined-backup", Version: 1}
	data, err := buildCombinedBackup(manifest, map[string]string{
		"managed-rules.json": `[]`,
		"packet.rules":       "*filter\nCOMMIT\n",
	})
	if err != nil {
		t.Fatalf("buildCombinedBackup() error = %v", err)
	}
	var document combinedBackupDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode combined backup: %v", err)
	}
	if document.Manifest.Format != manifest.Format || document.Manifest.Version != 1 {
		t.Fatalf("manifest = %#v", document.Manifest)
	}
	if document.Files["packet.rules"] != "*filter\nCOMMIT\n" || document.Files["managed-rules.json"] != `[]` {
		t.Fatalf("files = %#v", document.Files)
	}
}

func TestParseCombinedRestoreRestoresManagedMetadata(t *testing.T) {
	rules, err := json.Marshal([]*model.Rule{{
		ID: "managed", Backend: model.BackendPacket, Chain: "INPUT", Action: "ACCEPT", Position: 1, Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	document := combinedBackupDocument{
		Manifest: combinedBackupManifest{Format: "iptables-web-combined-backup", Version: 1, ManagedRulesFile: "managed-rules.json"},
		Files: map[string]string{
			"packet.rules":       "*filter\nCOMMIT\n",
			"packet-ipv6.rules":  "*filter\nCOMMIT\n",
			"managed-rules.json": string(rules),
		},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	packet, ipv6, managed, combined, err := parseRestoreDocument(string(data))
	if err != nil {
		t.Fatal(err)
	}
	if !combined || packet == "" || ipv6 == "" || len(managed) != 1 || managed[0].ID != "managed" {
		t.Fatalf("parsed restore = combined:%v packet:%q ipv6:%q managed:%#v", combined, packet, ipv6, managed)
	}
}

func TestParseRestoreRequestBodyAcceptsDirectCombinedJSON(t *testing.T) {
	document := combinedBackupDocument{
		Manifest: combinedBackupManifest{Format: "iptables-web-combined-backup", Version: 1},
		Files:    map[string]string{"packet.rules": "*filter\nCOMMIT\n"},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseRestoreRequestBody(raw)
	if err != nil {
		t.Fatalf("parseRestoreRequestBody() error = %v", err)
	}
	if got != string(raw) {
		t.Fatalf("direct restore body changed")
	}
}

func TestParseRestoreRequestBodyKeepsLegacyEnvelope(t *testing.T) {
	got, err := parseRestoreRequestBody([]byte(`{"data":"*filter\nCOMMIT\n"}`))
	if err != nil {
		t.Fatalf("parseRestoreRequestBody() error = %v", err)
	}
	if got != "*filter\nCOMMIT\n" {
		t.Fatalf("legacy restore data = %q", got)
	}
}

type pausedBackupMutationStore struct {
	store.Store
	entered chan struct{}
	resume  chan struct{}
}

func (s *pausedBackupMutationStore) Save() error {
	close(s.entered)
	<-s.resume
	return s.Store.Save()
}

func TestCompleteBackupWaitsForRuleMutation(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	s := &pausedBackupMutationStore{Store: store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json")), entered: make(chan struct{}), resume: make(chan struct{})}
	h := NewHandler(s, executor)
	mutationDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.CreateRule(rec, httptest.NewRequest("POST", "/api/v1/rules", strings.NewReader(`{"chain":"INPUT","action":"ACCEPT","position":1,"enabled":true}`)))
		mutationDone <- rec
	}()
	<-s.entered
	backupDone := make(chan *httptest.ResponseRecorder, 1)
	backupStarted := make(chan struct{})
	go func() {
		close(backupStarted)
		rec := httptest.NewRecorder()
		h.BackupRules(rec, httptest.NewRequest("GET", "/api/v1/system/backup?backend=all", nil))
		backupDone <- rec
	}()
	<-backupStarted
	var premature *httptest.ResponseRecorder
	select {
	case premature = <-backupDone:
	case <-time.After(100 * time.Millisecond):
	}
	close(s.resume)
	if created := <-mutationDone; created.Code != 201 {
		t.Fatalf("mutation: %d %s", created.Code, created.Body.String())
	}
	if premature != nil {
		t.Fatalf("backup read an uncommitted mutation: %s", premature.Body.String())
	}
	rec := <-backupDone
	if rec.Code != 200 {
		t.Fatalf("backup: %d %s", rec.Code, rec.Body.String())
	}
	var document combinedBackupDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	var rules []*model.Rule
	if err := json.Unmarshal([]byte(document.Files["managed-rules.json"]), &rules); err != nil || len(rules) != 1 {
		t.Fatalf("committed rules missing from backup: %v", err)
	}
}
