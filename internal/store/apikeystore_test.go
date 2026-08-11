package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIKeyStoreCreatesValidatesRevokesAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-keys.json")
	s := NewAPIKeyStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	metadata, plaintext, err := s.Create("controller-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plaintext, "ipw_") || !s.Validate(plaintext) || s.Validate("wrong") {
		t.Fatal("generated API key validation failed")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), plaintext) {
		t.Fatal("API key file contains plaintext credential")
	}
	reloaded := NewAPIKeyStore(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if !reloaded.Validate(plaintext) || len(reloaded.List()) != 1 {
		t.Fatal("reloaded API key was not valid")
	}
	if err := reloaded.Delete(metadata.ID); err != nil {
		t.Fatal(err)
	}
	if reloaded.Validate(plaintext) {
		t.Fatal("revoked API key is still valid")
	}
}
