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
