package api

import (
	"encoding/json"
	"testing"

	"iptables-web/internal/model"
)

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
