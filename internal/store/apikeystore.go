package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"iptables-web/internal/model"
)

// APIKeyStore manages dynamically reloadable API credentials. The in-memory
// set is updated atomically after each successful on-disk change.
type APIKeyStore struct {
	mu       sync.RWMutex
	filePath string
	keys     []*model.AccessKey
}

func NewAPIKeyStore(filePath string) *APIKeyStore {
	return &APIKeyStore{filePath: filePath, keys: []*model.AccessKey{}}
}

func (s *APIKeyStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.filePath)
	if errors.Is(err, os.ErrNotExist) {
		s.keys = []*model.AccessKey{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read API keys file: %w", err)
	}
	if len(data) == 0 {
		s.keys = []*model.AccessKey{}
		return nil
	}
	var keys []*model.AccessKey
	if err := json.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("decode API keys file: %w", err)
	}
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if key == nil || len(key.ID) != 24 || seen[key.ID] || strings.TrimSpace(key.Name) == "" {
			return fmt.Errorf("API keys file contains an invalid or duplicate key")
		}
		if digest, err := hex.DecodeString(key.Hash); err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("API key %s has an invalid digest", key.ID)
		}
		seen[key.ID] = true
	}
	s.keys = keys
	return os.Chmod(s.filePath, 0600)
}

func (s *APIKeyStore) List() []model.AccessKeyResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.AccessKeyResponse, 0, len(s.keys))
	for _, key := range s.keys {
		result = append(result, key.ToResponse())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result
}

func (s *APIKeyStore) Create(name string) (model.AccessKeyResponse, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 64 {
		return model.AccessKeyResponse{}, "", fmt.Errorf("key name is required and must not exceed 64 characters")
	}
	for _, existing := range s.keys {
		if strings.EqualFold(existing.Name, name) {
			return model.AccessKeyResponse{}, "", fmt.Errorf("key name already exists")
		}
	}
	idBytes := make([]byte, 12)
	secretBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return model.AccessKeyResponse{}, "", err
	}
	if _, err := io.ReadFull(rand.Reader, secretBytes); err != nil {
		return model.AccessKeyResponse{}, "", err
	}
	plaintext := "ipw_" + base64.RawURLEncoding.EncodeToString(secretBytes)
	digest := sha256.Sum256([]byte(plaintext))
	key := &model.AccessKey{
		ID: hex.EncodeToString(idBytes), Name: name,
		Hash: hex.EncodeToString(digest[:]), CreatedAt: time.Now(),
	}
	s.keys = append(s.keys, key)
	if err := s.saveLocked(); err != nil {
		s.keys = s.keys[:len(s.keys)-1]
		return model.AccessKeyResponse{}, "", err
	}
	return key.ToResponse(), plaintext, nil
}

func (s *APIKeyStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, key := range s.keys {
		if key.ID != id {
			continue
		}
		original := append([]*model.AccessKey(nil), s.keys...)
		s.keys = append(s.keys[:i], s.keys[i+1:]...)
		if err := s.saveLocked(); err != nil {
			s.keys = original
			return err
		}
		return nil
	}
	return fmt.Errorf("access key %s not found", id)
}

func (s *APIKeyStore) Validate(plaintext string) bool {
	if plaintext == "" {
		return false
	}
	digest := sha256.Sum256([]byte(plaintext))
	s.mu.RLock()
	defer s.mu.RUnlock()
	valid := 0
	for _, key := range s.keys {
		stored, err := hex.DecodeString(key.Hash)
		if err == nil && len(stored) == sha256.Size {
			valid |= subtle.ConstantTimeCompare(digest[:], stored)
		}
	}
	return valid == 1
}

func (s *APIKeyStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.keys, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomically(s.filePath, data, 0600)
}
