package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"iptables-web/internal/model"
	"os"
	"path/filepath"
	"sync"
)

// MonitoringStore is controller configuration, never an Agent credential or
// a setting that needs to be forwarded to a remote host.
type MonitoringStore struct {
	mu       sync.RWMutex
	filePath string
	policy   model.MonitoringPolicy
}

func NewMonitoringStore(path string) *MonitoringStore {
	return &MonitoringStore{filePath: path, policy: model.DefaultMonitoringPolicy()}
}

func (s *MonitoringStore) Load() error {
	if s.filePath == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.filePath)
	if errors.Is(err, os.ErrNotExist) {
		return s.saveLocked(s.policy)
	}
	if err != nil {
		return fmt.Errorf("read monitoring policy: %w", err)
	}
	policy := model.DefaultMonitoringPolicy()
	if err := json.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("decode monitoring policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	if err := os.Chmod(s.filePath, 0600); err != nil {
		return err
	}
	s.policy = policy
	return nil
}

func (s *MonitoringStore) Get() model.MonitoringPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}

func (s *MonitoringStore) Update(policy model.MonitoringPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.saveLocked(policy); err != nil {
		return err
	}
	s.policy = policy
	return nil
}

func (s *MonitoringStore) saveLocked(policy model.MonitoringPolicy) error {
	if s.filePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomically(s.filePath, data, 0600)
}
