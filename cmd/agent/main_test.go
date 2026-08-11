package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAgentKeyHashFromPrivateFile(t *testing.T) {
	t.Setenv("AGENT_KEY_SHA256", "")
	hash := sha256.Sum256([]byte("ipwa_test"))
	path := filepath.Join(t.TempDir(), "agent.key.sha256")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(hash[:])+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadAgentKeyHash(path)
	if err != nil || string(loaded) != string(hash[:]) {
		t.Fatalf("loaded=%x err=%v", loaded, err)
	}
}

func TestLoadAgentKeyHashRejectsPlaintext(t *testing.T) {
	t.Setenv("AGENT_KEY_SHA256", "ipwa_plaintext-must-not-be-accepted")
	if _, err := loadAgentKeyHash("unused"); err == nil {
		t.Fatal("plaintext Agent Key was accepted as a stored digest")
	}
}

func TestPrepareActiveEnrollmentPersistsIdentityAndOnlyKeyHash(t *testing.T) {
	t.Setenv("AGENT_KEY_SHA256", "")
	dir := t.TempDir()
	cfg := config{
		ManagerURL:   "http://127.0.0.1:33801",
		PublicURL:    "http://127.0.0.1:33802",
		IdentityFile: filepath.Join(dir, "private", "agent.identity"),
		KeyHashFile:  filepath.Join(dir, "private", "agent.key.sha256"),
	}
	hash, key, identity, err := prepareAgentEnrollment(cfg)
	if err != nil || key == "" || len(hash) != sha256.Size || len(identity) == 0 {
		t.Fatalf("first prepare hash=%x key_present=%v identity=%d err=%v", hash, key != "", len(identity), err)
	}
	for _, path := range []string{cfg.IdentityFile, cfg.KeyHashFile} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat private file %s: %v", path, statErr)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("private file %s mode=%v", path, info.Mode().Perm())
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil || bytes.Contains(data, []byte(key)) {
			t.Fatalf("private file %s contains plaintext key or cannot be read: %v", path, readErr)
		}
	}

	reloadedHash, reloadedKey, reloadedIdentity, err := prepareAgentEnrollment(cfg)
	if err != nil || reloadedKey != "" || !bytes.Equal(hash, reloadedHash) || !bytes.Equal(identity, reloadedIdentity) {
		t.Fatalf("restart changed enrollment secrets: key=%q err=%v", reloadedKey, err)
	}
}

func TestEnrollmentURLsRejectPathsAndCredentials(t *testing.T) {
	for _, raw := range []string{"http://user:pass@manager:33801", "http://manager:33801/path", "ftp://manager"} {
		if _, err := normalizedEnrollmentURL(raw); err == nil {
			t.Fatalf("unsafe MANAGER_URL %q accepted", raw)
		}
	}
	if got, err := normalizedEnrollmentURL("https://manager.example:33801/"); err != nil || got != "https://manager.example:33801/api/v1/agent-enrollments/register" {
		t.Fatalf("normalized URL=%q err=%v", got, err)
	}
}
