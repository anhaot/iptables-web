package change

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"iptables-web/internal/model"
)

type RuleChange struct {
	ID     string      `json:"id"`
	Before *model.Rule `json:"before,omitempty"`
	After  *model.Rule `json:"after,omitempty"`
}

type UserChange struct {
	ID     string              `json:"id"`
	Before *model.UserResponse `json:"before,omitempty"`
	After  *model.UserResponse `json:"after,omitempty"`
}

type AuditEvent struct {
	ID          string       `json:"id"`
	CreatedAt   time.Time    `json:"created_at"`
	RequestID   string       `json:"request_id,omitempty"`
	Actor       string       `json:"actor"`
	Role        string       `json:"role,omitempty"`
	RemoteIP    string       `json:"remote_ip,omitempty"`
	Method      string       `json:"method"`
	Path        string       `json:"path"`
	Action      string       `json:"action"`
	Status      int          `json:"status"`
	RuleChanges []RuleChange `json:"rule_changes,omitempty"`
	UserChanges []UserChange `json:"user_changes,omitempty"`
}

type RollbackState struct {
	ID        string        `json:"id"`
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	Action    string        `json:"action"`
	Actor     string        `json:"actor"`
	Rules     []*model.Rule `json:"rules"`
}

type Manager struct {
	mu           sync.Mutex
	auditPath    string
	rollbackPath string
	window       time.Duration
}

func NewManager(auditPath, rollbackPath string, window time.Duration) *Manager {
	if window <= 0 {
		window = 10 * time.Minute
	}
	return &Manager{auditPath: auditPath, rollbackPath: rollbackPath, window: window}
}

func (m *Manager) Record(event AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.auditPath == "" {
		return nil
	}
	if event.ID == "" {
		event.ID = newID()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.auditPath), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(m.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(append(data, '\n')); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(m.auditPath, 0600)
}

func (m *Manager) List(limit int) ([]AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlimited := limit == -1
	if !unlimited && (limit <= 0 || limit > 1000) {
		limit = 100
	}
	file, err := os.Open(m.auditPath)
	if errors.Is(err, os.ErrNotExist) || m.auditPath == "" {
		return []AuditEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	events := make([]AuditEvent, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var event AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("parse audit event: %w", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(events, func(i, j int) bool { return events[i].CreatedAt.After(events[j].CreatedAt) })
	if !unlimited && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func (m *Manager) SaveRollback(action, actor string, rules []*model.Rule) (*RollbackState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	state := &RollbackState{
		ID:        newID(),
		CreatedAt: now,
		ExpiresAt: now.Add(m.window),
		Action:    action,
		Actor:     actor,
		Rules:     cloneRules(rules),
	}
	if m.rollbackPath == "" {
		return state, nil
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeAtomically(m.rollbackPath, data, 0600); err != nil {
		return nil, err
	}
	return state, nil
}

func (m *Manager) RollbackStatus() (*RollbackState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rollbackPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(m.rollbackPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state RollbackState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if time.Now().After(state.ExpiresAt) {
		return nil, nil
	}
	state.Rules = cloneRules(state.Rules)
	return &state, nil
}

func DiffRules(before, after []*model.Rule) []RuleChange {
	beforeByID := make(map[string]*model.Rule, len(before))
	afterByID := make(map[string]*model.Rule, len(after))
	for _, rule := range before {
		if rule != nil {
			beforeByID[rule.ID] = rule
		}
	}
	for _, rule := range after {
		if rule != nil {
			afterByID[rule.ID] = rule
		}
	}
	ids := unionIDs(beforeByID, afterByID)
	changes := make([]RuleChange, 0)
	for _, id := range ids {
		oldRule, oldOK := beforeByID[id]
		newRule, newOK := afterByID[id]
		if oldOK && newOK && equalJSON(oldRule, newRule) {
			continue
		}
		change := RuleChange{ID: id}
		if oldOK {
			change.Before = cloneRule(oldRule)
		}
		if newOK {
			change.After = cloneRule(newRule)
		}
		changes = append(changes, change)
	}
	return changes
}

func DiffUsers(before, after []model.UserResponse) []UserChange {
	beforeByID := make(map[string]model.UserResponse, len(before))
	afterByID := make(map[string]model.UserResponse, len(after))
	for _, user := range before {
		beforeByID[user.ID] = user
	}
	for _, user := range after {
		afterByID[user.ID] = user
	}
	ids := unionUserIDs(beforeByID, afterByID)
	changes := make([]UserChange, 0)
	for _, id := range ids {
		oldUser, oldOK := beforeByID[id]
		newUser, newOK := afterByID[id]
		if oldOK && newOK && equalJSON(oldUser, newUser) {
			continue
		}
		change := UserChange{ID: id}
		if oldOK {
			copy := oldUser
			change.Before = &copy
		}
		if newOK {
			copy := newUser
			change.After = &copy
		}
		changes = append(changes, change)
	}
	return changes
}

func unionIDs(a, b map[string]*model.Rule) []string {
	set := make(map[string]bool, len(a)+len(b))
	for id := range a {
		set[id] = true
	}
	for id := range b {
		set[id] = true
	}
	return sortedKeys(set)
}

func unionUserIDs(a, b map[string]model.UserResponse) []string {
	set := make(map[string]bool, len(a)+len(b))
	for id := range a {
		set[id] = true
	}
	for id := range b {
		set[id] = true
	}
	return sortedKeys(set)
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func equalJSON(a, b interface{}) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

func cloneRules(rules []*model.Rule) []*model.Rule {
	result := make([]*model.Rule, len(rules))
	for i, rule := range rules {
		result[i] = cloneRule(rule)
	}
	return result
}

func cloneRule(rule *model.Rule) *model.Rule {
	if rule == nil {
		return nil
	}
	copy := *rule
	return &copy
}

func writeAtomically(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func newID() string {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}
