package store

import (
	"iptables-web/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func TestMonitoringDefaultsPersistAndOverridesInherit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "monitoring-policy.json")
	s := NewMonitoringStore(path)
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	if got := s.Get(); got != model.DefaultMonitoringPolicy() {
		t.Fatalf("defaults=%+v", got)
	}
	policy := model.MonitoringPolicy{ProbeIntervalSeconds: 120, OfflineAfterSeconds: 90}
	if err := s.Update(policy); err != nil {
		t.Fatal(err)
	}
	loaded := NewMonitoringStore(path)
	if err := loaded.Load(); err != nil {
		t.Fatal(err)
	}
	if loaded.Get() != policy {
		t.Fatal("settings did not persist")
	}
	if got := policy.ForHost(&model.ManagedHost{ProbeIntervalSeconds: 30}); got.ProbeIntervalSeconds != 30 || got.OfflineAfterSeconds != 90 {
		t.Fatalf("override=%+v", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("settings permissions")
	}
	for _, bad := range []model.MonitoringPolicy{{ProbeIntervalSeconds: 14, OfflineAfterSeconds: 45}, {ProbeIntervalSeconds: 60, OfflineAfterSeconds: 29}} {
		if err := s.Update(bad); err == nil {
			t.Fatal("invalid settings accepted")
		}
	}
	if s.Get() != policy {
		t.Fatal("validation failure changed policy")
	}
}

func TestMonitoringPersistenceFailurePreservesPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(path, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewMonitoringStore(filepath.Join(path, "settings.json"))
	if err := s.Update(model.MonitoringPolicy{ProbeIntervalSeconds: 90, OfflineAfterSeconds: 60}); err == nil {
		t.Fatal("save should fail")
	}
	if s.Get() != model.DefaultMonitoringPolicy() {
		t.Fatal("failed save changed live policy")
	}
}
