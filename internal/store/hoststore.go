package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

// HostStore persists the remote host inventory. Remote API keys are encrypted
// with AES-GCM using an automatically generated key file or the optional
// HOST_CREDENTIAL_KEY override before they reach disk.
type HostStore struct {
	mu            sync.RWMutex
	filePath      string
	keyPath       string
	key           []byte
	keyErr        error
	hosts         []*model.ManagedHost
	lastSeenSaved map[string]time.Time
}

func NewHostStore(filePath, credentialKey string) *HostStore {
	var key []byte
	var keyErr error
	credentialKey = strings.TrimSpace(credentialKey)
	if credentialKey != "" && len([]byte(credentialKey)) < 32 {
		keyErr = fmt.Errorf("HOST_CREDENTIAL_KEY must contain at least 32 characters when configured")
	} else if credentialKey != "" {
		sum := sha256.Sum256([]byte(credentialKey))
		key = sum[:]
	}
	base := filepath.Base(filePath)
	ext := filepath.Ext(base)
	keyName := strings.TrimSuffix(base, ext) + ".key"
	return &HostStore{
		filePath:      filePath,
		keyPath:       filepath.Join(filepath.Dir(filePath), keyName),
		key:           key,
		keyErr:        keyErr,
		hosts:         []*model.ManagedHost{},
		lastSeenSaved: make(map[string]time.Time),
	}
}

func (s *HostStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.filePath)
	if errors.Is(err, os.ErrNotExist) {
		s.hosts = []*model.ManagedHost{}
		s.lastSeenSaved = make(map[string]time.Time)
		return s.ensureKeyLocked(true)
	}
	if err != nil {
		return fmt.Errorf("read hosts file: %w", err)
	}
	if len(data) == 0 {
		s.hosts = []*model.ManagedHost{}
		s.lastSeenSaved = make(map[string]time.Time)
		return s.ensureKeyLocked(true)
	}
	if err := json.Unmarshal(data, &s.hosts); err != nil {
		return fmt.Errorf("decode hosts file: %w", err)
	}
	hasEncryptedCredentials := false
	for _, host := range s.hosts {
		if host != nil && host.APIKeyCipher != "" {
			hasEncryptedCredentials = true
			break
		}
	}
	// Do not silently generate a replacement key for an existing encrypted
	// inventory: that would make the credentials permanently unreadable.
	if err := s.ensureKeyLocked(!hasEncryptedCredentials); err != nil {
		return err
	}
	seen := make(map[string]bool, len(s.hosts))
	seenAgents := make(map[string]bool, len(s.hosts))
	s.lastSeenSaved = make(map[string]time.Time, len(s.hosts))
	for _, host := range s.hosts {
		if host == nil || host.ID == "" || seen[host.ID] {
			return fmt.Errorf("hosts file contains an invalid or duplicate host id")
		}
		if err := model.ValidateMonitoringOverrides(host.ProbeIntervalSeconds, host.OfflineAfterSeconds); err != nil {
			return fmt.Errorf("invalid monitoring settings for host %s: %w", host.ID, err)
		}
		seen[host.ID] = true
		if host.AgentID != "" {
			if seenAgents[host.AgentID] {
				return fmt.Errorf("hosts file contains a duplicate Agent identity")
			}
			seenAgents[host.AgentID] = true
		}
		if host.AgentLastSeenAt != nil {
			s.lastSeenSaved[host.ID] = *host.AgentLastSeenAt
		}
		if host.APIKeyCipher != "" {
			if _, err := s.decryptLocked(host.APIKeyCipher); err != nil {
				return fmt.Errorf("decrypt credentials for host %s: %w", host.ID, err)
			}
		}
	}
	return os.Chmod(s.filePath, 0600)
}

// MarkAgentSeen records a verified, signed Agent heartbeat. The latest value
// is immediately visible in API responses while persistence is throttled to
// once per minute per host to avoid continuous disk writes.
func (s *HostStore) MarkAgentSeen(agentID string, seenAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, host := range s.hosts {
		if agentID == "" || host.AgentID != agentID {
			continue
		}
		seenAt = seenAt.UTC()
		if host.AgentLastSeenAt != nil && !seenAt.After(*host.AgentLastSeenAt) {
			return nil
		}
		host.AgentLastSeenAt = &seenAt
		lastSaved := s.lastSeenSaved[host.ID]
		if !lastSaved.IsZero() && seenAt.Sub(lastSaved) < time.Minute {
			return nil
		}
		if err := s.saveLocked(); err != nil {
			return err
		}
		s.lastSeenSaved[host.ID] = seenAt
		return nil
	}
	return fmt.Errorf("Agent %s is not managed", agentID)
}

func (s *HostStore) List() []model.ManagedHostResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.ManagedHostResponse, 0, len(s.hosts))
	for _, host := range s.hosts {
		result = append(result, host.ToResponse())
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Group != result[j].Group {
			return result[i].Group < result[j].Group
		}
		return result[i].Name < result[j].Name
	})
	return result
}

func (s *HostStore) Get(id string) (*model.ManagedHost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, host := range s.hosts {
		if host.ID == id {
			return cloneHost(host), nil
		}
	}
	return nil, fmt.Errorf("host %s not found", id)
}

func (s *HostStore) GetByAgentID(agentID string) (*model.ManagedHost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, host := range s.hosts {
		if agentID != "" && host.AgentID == agentID {
			return cloneHost(host), nil
		}
	}
	return nil, fmt.Errorf("Agent %s is not managed", agentID)
}

// GetWithAPIKey returns a copy with APIKeyCipher replaced by the decrypted API
// key. It is only intended for the controller's outbound client.
func (s *HostStore) GetWithAPIKey(id string) (*model.ManagedHost, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, host := range s.hosts {
		if host.ID != id {
			continue
		}
		apiKey, err := s.decryptLocked(host.APIKeyCipher)
		if err != nil {
			return nil, "", err
		}
		return cloneHost(host), apiKey, nil
	}
	return nil, "", fmt.Errorf("host %s not found", id)
}

func (s *HostStore) Create(host *model.ManagedHost, apiKey string) error {
	if err := model.ValidateMonitoringOverrides(host.ProbeIntervalSeconds, host.OfflineAfterSeconds); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureKeyLocked(true); err != nil {
		return err
	}
	if strings.TrimSpace(apiKey) == "" {
		return fmt.Errorf("remote API key is required")
	}
	for _, existing := range s.hosts {
		if existing.ID == host.ID || strings.EqualFold(existing.Name, host.Name) {
			return fmt.Errorf("host id or name already exists")
		}
		if host.AgentID != "" && existing.AgentID == host.AgentID {
			return fmt.Errorf("Agent is already managed")
		}
	}
	ciphertext, err := s.encryptLocked(apiKey)
	if err != nil {
		return err
	}
	now := time.Now()
	host.APIKeyCipher = ciphertext
	host.CreatedAt = now
	host.UpdatedAt = now
	s.hosts = append(s.hosts, cloneHost(host))
	if err := s.saveLocked(); err != nil {
		s.hosts = s.hosts[:len(s.hosts)-1]
		return err
	}
	if host.AgentLastSeenAt != nil {
		s.lastSeenSaved[host.ID] = *host.AgentLastSeenAt
	}
	return nil
}

// UpdateMetadata rejects stale connection settings while preserving the latest
// signed heartbeat. Browser metadata edits must never revert an approved address.
func (s *HostStore) UpdateMetadata(expected, host *model.ManagedHost) error {
	return s.update(host, "", expected)
}

func (s *HostStore) Update(host *model.ManagedHost, newAPIKey string) error {
	return s.update(host, newAPIKey, nil)
}

func (s *HostStore) update(host *model.ManagedHost, newAPIKey string, expected *model.ManagedHost) error {
	if err := model.ValidateMonitoringOverrides(host.ProbeIntervalSeconds, host.OfflineAfterSeconds); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.hosts {
		if existing.ID != host.ID {
			continue
		}
		if expected != nil && (expected.ID != host.ID || existing.BaseURL != expected.BaseURL ||
			existing.CAPEM != expected.CAPEM || existing.AgentID != expected.AgentID ||
			existing.AgentPublicKey != expected.AgentPublicKey || existing.APIKeyCipher != expected.APIKeyCipher) {
			return fmt.Errorf("Agent connection changed while editing; refresh and retry")
		}
		for j, other := range s.hosts {
			if i != j && strings.EqualFold(other.Name, host.Name) {
				return fmt.Errorf("host name already exists")
			}
			if i != j && host.AgentID != "" && other.AgentID == host.AgentID {
				return fmt.Errorf("Agent is already managed")
			}
		}
		updated := cloneHost(host)
		updated.CreatedAt = existing.CreatedAt
		updated.UpdatedAt = time.Now()
		updated.APIKeyCipher = existing.APIKeyCipher
		if existing.AgentLastSeenAt != nil && (updated.AgentLastSeenAt == nil || existing.AgentLastSeenAt.After(*updated.AgentLastSeenAt)) {
			updated.AgentLastSeenAt = cloneTimePointer(existing.AgentLastSeenAt)
		}
		if strings.TrimSpace(newAPIKey) != "" {
			if err := s.ensureKeyLocked(true); err != nil {
				return err
			}
			ciphertext, err := s.encryptLocked(newAPIKey)
			if err != nil {
				return err
			}
			updated.APIKeyCipher = ciphertext
		}
		s.hosts[i] = updated
		if err := s.saveLocked(); err != nil {
			s.hosts[i] = existing
			return err
		}
		return nil
	}
	return fmt.Errorf("host %s not found", host.ID)
}

// UpdateAgentConnection commits a verified endpoint and credential while
// preserving administrator metadata changed during the network probe.
func (s *HostStore) UpdateAgentConnection(expected *model.ManagedHost, baseURL, caPEM, newAPIKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected == nil || strings.TrimSpace(newAPIKey) == "" {
		return fmt.Errorf("Agent identity and new key are required")
	}
	for i, existing := range s.hosts {
		if existing.ID != expected.ID {
			continue
		}
		if existing.AgentID != expected.AgentID || existing.AgentPublicKey != expected.AgentPublicKey ||
			existing.BaseURL != expected.BaseURL || existing.CAPEM != expected.CAPEM || existing.APIKeyCipher != expected.APIKeyCipher {
			return fmt.Errorf("Agent identity or endpoint changed during verification; retry registration")
		}
		ciphertext, err := s.encryptLocked(newAPIKey)
		if err != nil {
			return err
		}
		updated := cloneHost(existing)
		updated.BaseURL = baseURL
		updated.CAPEM = caPEM
		updated.APIKeyCipher = ciphertext
		updated.UpdatedAt = time.Now()
		s.hosts[i] = updated
		if err := s.saveLocked(); err != nil {
			s.hosts[i] = existing
			return err
		}
		return nil
	}
	return fmt.Errorf("host %s not found", expected.ID)
}

func (s *HostStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, host := range s.hosts {
		if host.ID != id {
			continue
		}
		original := append([]*model.ManagedHost(nil), s.hosts...)
		s.hosts = append(s.hosts[:i], s.hosts[i+1:]...)
		if err := s.saveLocked(); err != nil {
			s.hosts = original
			return err
		}
		delete(s.lastSeenSaved, id)
		return nil
	}
	return fmt.Errorf("host %s not found", id)
}

func (s *HostStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.hosts, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomically(s.filePath, data, 0600)
}

func (s *HostStore) ensureKeyLocked(create bool) error {
	if s.keyErr != nil {
		return s.keyErr
	}
	if len(s.key) == 32 {
		return nil
	}
	data, err := os.ReadFile(s.keyPath)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return fmt.Errorf("host credential key file %s is missing; restore it with hosts.json or configure HOST_CREDENTIAL_KEY", s.keyPath)
		}
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return fmt.Errorf("generate host credential key: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(s.keyPath), 0700); err != nil {
			return fmt.Errorf("create host credential key directory: %w", err)
		}
		encoded := base64.RawStdEncoding.EncodeToString(key) + "\n"
		if err := writeFileAtomically(s.keyPath, []byte(encoded), 0600); err != nil {
			return fmt.Errorf("save host credential key: %w", err)
		}
		s.key = key
		return nil
	}
	if err != nil {
		return fmt.Errorf("read host credential key: %w", err)
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("host credential key file %s is invalid", s.keyPath)
	}
	s.key = decoded
	return os.Chmod(s.keyPath, 0600)
}

func (s *HostStore) encryptLocked(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (s *HostStore) decryptLocked(encoded string) (string, error) {
	if encoded == "" {
		return "", fmt.Errorf("remote host has no API key")
	}
	if len(s.key) == 0 {
		return "", fmt.Errorf("host credential encryption key is not available")
	}
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("encrypted credential is truncated")
	}
	plaintext, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("credential authentication failed")
	}
	return string(plaintext), nil
}

func cloneHost(host *model.ManagedHost) *model.ManagedHost {
	if host == nil {
		return nil
	}
	copy := *host
	copy.AgentLastSeenAt = cloneTimePointer(host.AgentLastSeenAt)
	return &copy
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
