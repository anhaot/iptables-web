package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"iptables-web/internal/model"
)

func TestHostStoreEncryptsCredentialsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.json")
	credentialKey := "test-controller-credential-key-at-least-32-characters"
	store := NewHostStore(path, credentialKey)
	host := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", BaseURL: "https://node-a.example", Enabled: true}
	if err := store.Create(host, "remote-secret-api-key"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "remote-secret-api-key") {
		t.Fatal("hosts file contains the plaintext API key")
	}

	reloaded := NewHostStore(path, credentialKey)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	got, key, err := reloaded.GetWithAPIKey(host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if key != "remote-secret-api-key" || got.Name != "node-a" {
		t.Fatalf("reloaded host/key = %#v, %q", got, key)
	}
	responseJSON := string(mustJSON(t, got.ToResponse()))
	if strings.Contains(responseJSON, "remote-secret-api-key") || strings.Contains(responseJSON, got.APIKeyCipher) {
		t.Fatal("safe host response exposed credential material")
	}
}

func TestHostStoreRequiresStableCredentialKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.json")
	store := NewHostStore(path, "first-controller-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", BaseURL: "https://node-a.example", Enabled: true}
	if err := store.Create(host, "secret"); err != nil {
		t.Fatal(err)
	}
	if err := NewHostStore(path, "different-controller-key-at-least-32-chars").Load(); err == nil {
		t.Fatal("Load succeeded with a different credential key")
	}
	if err := NewHostStore(path, "").Load(); err == nil {
		t.Fatal("Load succeeded without HOST_CREDENTIAL_KEY")
	}
}

func TestHostStoreAutomaticallyGeneratesAndReloadsCredentialKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	store := NewHostStore(path, "")
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "hosts.key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("automatic key was not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("hosts.key mode = %o, want 600", info.Mode().Perm())
	}
	host := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", BaseURL: "http://192.168.1.10:33801", Enabled: true}
	if err := store.Create(host, "dynamic-target-key"); err != nil {
		t.Fatal(err)
	}
	reloaded := NewHostStore(path, "")
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	_, key, err := reloaded.GetWithAPIKey(host.ID)
	if err != nil || key != "dynamic-target-key" {
		t.Fatalf("reloaded key = %q, err = %v", key, err)
	}
}

func TestHostStoreRejectsDuplicateAgentIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.json")
	store := NewHostStore(path, "controller-test-key-at-least-32-characters")
	first := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", BaseURL: "http://192.0.2.10:33802", AgentID: "aabbccddeeff001122334455", Enabled: true}
	second := &model.ManagedHost{ID: "112233445566778899aabbcc", Name: "node-b", BaseURL: "http://192.0.2.11:33802", AgentID: first.AgentID, Enabled: true}
	if err := store.Create(first, "first-secret"); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(second, "second-secret"); err == nil {
		t.Fatal("duplicate Agent identity was accepted")
	}
}

func TestHostStoreRecordsAndPersistsAgentHeartbeat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.json")
	credentialKey := "controller-test-key-at-least-32-characters"
	hosts := NewHostStore(path, credentialKey)
	host := &model.ManagedHost{
		ID: "00112233445566778899aabb", Name: "node-a",
		BaseURL: "http://192.0.2.10:33802", AgentID: "aabbccddeeff001122334455", Enabled: true,
	}
	if err := hosts.Create(host, "remote-secret"); err != nil {
		t.Fatal(err)
	}
	seenAt := time.Date(2026, time.August, 5, 12, 30, 0, 0, time.UTC)
	if err := hosts.MarkAgentSeen(host.AgentID, seenAt); err != nil {
		t.Fatal(err)
	}
	got, err := hosts.Get(host.ID)
	if err != nil || got.AgentLastSeenAt == nil || !got.AgentLastSeenAt.Equal(seenAt) {
		t.Fatalf("heartbeat = %#v, err = %v", got, err)
	}

	reloaded := NewHostStore(path, credentialKey)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	got, err = reloaded.Get(host.ID)
	if err != nil || got.AgentLastSeenAt == nil || !got.AgentLastSeenAt.Equal(seenAt) {
		t.Fatalf("reloaded heartbeat = %#v, err = %v", got, err)
	}
	if strings.Contains(string(mustJSON(t, got.ToResponse())), "remote-secret") {
		t.Fatal("heartbeat response exposed the Agent key")
	}
}

func mustJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAgentConnectionUpdatePreservesConcurrentMetadataAndChecksEndpoint(t *testing.T) {
	s := NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "host", Name: "old", Group: "old", AgentID: "agent", AgentPublicKey: "public", BaseURL: "http://192.0.2.1:33802", Enabled: true}
	if err := s.Create(host, "old-key"); err != nil {
		t.Fatal(err)
	}
	probeSnapshot, _ := s.Get(host.ID)
	adminEdit, _ := s.Get(host.ID)
	adminEdit.Name, adminEdit.Group, adminEdit.Enabled = "new-name", "new-group", false
	if err := s.Update(adminEdit, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAgentConnection(probeSnapshot, probeSnapshot.BaseURL, probeSnapshot.CAPEM, "new-key"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAgentConnection(probeSnapshot, probeSnapshot.BaseURL, probeSnapshot.CAPEM, "stale-key"); err == nil {
		t.Fatal("a stale concurrent credential verification was accepted")
	}
	updated, key, err := s.GetWithAPIKey(host.ID)
	if err != nil || updated.Name != "new-name" || updated.Group != "new-group" || updated.Enabled || key != "new-key" {
		t.Fatalf("stale probe overwrote metadata: %#v, %v", updated, err)
	}
	changedEndpoint := *updated
	changedEndpoint.BaseURL = "http://192.0.2.2:33802"
	if err := s.Update(&changedEndpoint, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAgentConnection(updated, updated.BaseURL, updated.CAPEM, "wrong-key"); err == nil {
		t.Fatal("stale endpoint accepted")
	}
	_, key, _ = s.GetWithAPIKey(host.ID)
	if key != "new-key" {
		t.Fatal("stale verification replaced the credential")
	}
}

func TestAgentHeartbeatNeverMovesBackwards(t *testing.T) {
	s := NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "host", Name: "node", AgentID: "agent", BaseURL: "http://192.0.2.1:33802"}
	if err := s.Create(host, "key"); err != nil {
		t.Fatal(err)
	}
	latest := time.Now().UTC()
	if err := s.MarkAgentSeen(host.AgentID, latest); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkAgentSeen(host.AgentID, latest.Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(host.ID)
	if got.AgentLastSeenAt == nil || !got.AgentLastSeenAt.Equal(latest) {
		t.Fatalf("heartbeat moved backwards: %v", got.AgentLastSeenAt)
	}
}

func TestHostMetadataUpdateCannotRevertAgentConnectionOrHeartbeat(t *testing.T) {
	s := NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "host", Name: "node", AgentID: "agent", AgentPublicKey: "public", BaseURL: "http://192.0.2.1:33802", Enabled: true}
	if err := s.Create(host, "old-key"); err != nil {
		t.Fatal(err)
	}
	oldSeen := time.Now().Add(-time.Minute).UTC()
	if err := s.MarkAgentSeen(host.AgentID, oldSeen); err != nil {
		t.Fatal(err)
	}
	expected, _ := s.Get(host.ID)
	edit := cloneHost(expected)
	edit.Name = "renamed"
	latest := time.Now().UTC()
	if err := s.MarkAgentSeen(host.AgentID, latest); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateMetadata(expected, edit); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(host.ID)
	if got.Name != "renamed" || got.AgentLastSeenAt == nil || !got.AgentLastSeenAt.Equal(latest) {
		t.Fatal("metadata edit reverted the heartbeat")
	}
	if err := s.UpdateAgentConnection(got, "http://192.0.2.2:33802", "", "rotated-key"); err != nil {
		t.Fatal(err)
	}
	edit.Name = "stale-edit"
	if err := s.UpdateMetadata(expected, edit); err == nil {
		t.Fatal("stale connection accepted")
	}
	got, key, err := s.GetWithAPIKey(host.ID)
	if err != nil || got.BaseURL != "http://192.0.2.2:33802" || key != "rotated-key" || got.Name != "renamed" {
		t.Fatal("stale metadata edit changed the connection or name")
	}
	reloaded := NewHostStore(s.filePath, "controller-test-key-at-least-32-characters")
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	got, _ = reloaded.Get(host.ID)
	if got.AgentLastSeenAt == nil || !got.AgentLastSeenAt.Equal(latest) {
		t.Fatal("latest heartbeat was not persisted")
	}
}
