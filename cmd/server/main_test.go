package main

import (
	"path/filepath"
	"testing"

	"iptables-web/internal/iptables"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

func TestLoadConfigDefaultsToExternalListenAddress(t *testing.T) {
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("RULES_FILE", "")
	t.Setenv("USERS_FILE", "")
	cfg := LoadConfig()
	if cfg.ListenAddr != "0.0.0.0:33801" {
		t.Fatalf("ListenAddr = %q, want %q", cfg.ListenAddr, "0.0.0.0:33801")
	}
}

func TestRemoveLegacyFirewalldRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	s := store.NewJSONStore(path)
	if err := s.Create(&model.Rule{ID: "legacy", Backend: "firewalld", Chain: "INPUT", Position: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(&model.Rule{ID: "packet", Backend: model.BackendPacket, Chain: "INPUT", Position: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	removed, err := removeLegacyFirewalldRules(s, path)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d", removed)
	}
	if _, err := s.Get("packet"); err != nil {
		t.Fatal("packet rule was removed")
	}
}

func TestLoadConfigAllowsLocalOnlyOverride(t *testing.T) {
	t.Setenv("LISTEN_ADDR", "127.0.0.1:33801")
	cfg := LoadConfig()
	if cfg.ListenAddr != "127.0.0.1:33801" {
		t.Fatalf("ListenAddr = %q, want local-only override", cfg.ListenAddr)
	}
}

func TestMigrateLegacyDockerDPortRules(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	path := filepath.Join(t.TempDir(), "rules.json")
	s := store.NewJSONStore(path)
	legacy := &model.Rule{
		ID: "legacy-docker", Backend: model.BackendPacket, Chain: "DOCKER_USER", Action: "ACCEPT",
		Protocol: "tcp", Source: "192.168.220.0/24", DPort: "18080", OriginalDPort: "18080", Position: 1, Enabled: true,
	}
	if err := s.Create(legacy); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	exe, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := migrateLegacyDockerDPortRules(s, exe)
	if err != nil {
		t.Fatal(err)
	}
	if migrated != 1 {
		t.Fatalf("migrated = %d", migrated)
	}
	got, err := s.Get("legacy-docker")
	if err != nil {
		t.Fatal(err)
	}
	if got.DPort != "" || got.OriginalDPort != "18080" {
		t.Fatalf("migrated rule = %#v", got)
	}
}
