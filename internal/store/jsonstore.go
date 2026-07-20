package store

import (
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

type JSONStore struct {
	mu       sync.RWMutex
	filePath string
	rules    []*model.Rule
}

func NewJSONStore(filePath string) *JSONStore {
	return &JSONStore{filePath: filePath}
}

func (s *JSONStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if errors.Is(err, os.ErrNotExist) {
		s.rules = []*model.Rule{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read rules file: %w", err)
	}
	if len(data) == 0 {
		s.rules = []*model.Rule{}
		return nil
	}
	if err := json.Unmarshal(data, &s.rules); err != nil {
		return err
	}
	s.normalizePositionsLocked()
	return nil
}

func (s *JSONStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return fmt.Errorf("create rules directory: %w", err)
	}

	data, err := json.MarshalIndent(s.rules, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}

	if err := writeFileAtomically(s.filePath, data, 0600); err != nil {
		return fmt.Errorf("write tmp file: %w", err)
	}
	return nil
}

func (s *JSONStore) List(chain string) ([]*model.Rule, error) {
	return s.listByBackend("", chain)
}

func (s *JSONStore) ListByBackend(backend, chain string) ([]*model.Rule, error) {
	return s.listByBackend(model.NormalizeBackend(backend), chain)
}

func (s *JSONStore) ListByTarget(backend, chain string) ([]*model.Rule, error) {
	backend = model.NormalizeBackend(backend)
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*model.Rule, 0)
	for _, r := range s.rules {
		if sameTarget(r, backend, chain) {
			result = append(result, cloneRule(r))
		}
	}
	sortRules(result)
	return result, nil
}

func (s *JSONStore) listByBackend(backend, chain string) ([]*model.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*model.Rule, 0)
	for _, r := range s.rules {
		if (backend == "" || r.Backend == backend) && (chain == "" || r.Chain == chain) {
			result = append(result, cloneRule(r))
		}
	}
	sortRules(result)
	return result, nil
}

func (s *JSONStore) Get(id string) (*model.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, r := range s.rules {
		if r.ID == id {
			return cloneRule(r), nil
		}
	}
	return nil, fmt.Errorf("rule %s not found", id)
}

func (s *JSONStore) Create(rule *model.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rule.Backend = model.NormalizeBackend(rule.Backend)
	if rule.Position == 0 {
		rule.Position = s.nextPosition(rule.Backend, rule.Chain)
	} else {
		max := s.nextPosition(rule.Backend, rule.Chain)
		if rule.Position > max {
			rule.Position = max
		}
		for _, r := range s.rules {
			if sameTarget(r, rule.Backend, rule.Chain) && r.Position >= rule.Position {
				r.Position++
				r.UpdatedAt = time.Now()
			}
		}
	}
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	s.rules = append(s.rules, cloneRule(rule))
	return nil
}

func (s *JSONStore) Update(rule *model.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, r := range s.rules {
		if r.ID == rule.ID {
			rule.Backend = model.NormalizeBackend(rule.Backend)
			oldBackend := r.Backend
			oldChain := r.Chain
			oldPosition := r.Position
			if rule.Position == 0 {
				rule.Position = oldPosition
			}
			rule.UpdatedAt = time.Now()
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			s.compactTarget(oldBackend, oldChain)
			max := s.nextPosition(rule.Backend, rule.Chain)
			if rule.Position > max {
				rule.Position = max
			}
			for _, other := range s.rules {
				if sameTarget(other, rule.Backend, rule.Chain) && other.Position >= rule.Position {
					other.Position++
					other.UpdatedAt = time.Now()
				}
			}
			s.rules = append(s.rules, cloneRule(rule))
			return nil
		}
	}
	return fmt.Errorf("rule %s not found", rule.ID)
}

func (s *JSONStore) Delete(id string) (*model.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, r := range s.rules {
		if r.ID == id {
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			s.compactTarget(r.Backend, r.Chain)
			return cloneRule(r), nil
		}
	}
	return nil, fmt.Errorf("rule %s not found", id)
}

func (s *JSONStore) Toggle(id string) (*model.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, r := range s.rules {
		if r.ID == id {
			r.Enabled = !r.Enabled
			r.UpdatedAt = time.Now()
			return cloneRule(r), nil
		}
	}
	return nil, fmt.Errorf("rule %s not found", id)
}

func (s *JSONStore) Reorder(chain string, ids []string) error {
	return s.ReorderByBackend(model.BackendPacket, chain, ids)
}

func (s *JSONStore) ReorderByBackend(backend, chain string, ids []string) error {
	return s.ReorderByTarget(backend, chain, ids)
}

func (s *JSONStore) ReorderByTarget(backend, chain string, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	backend = model.NormalizeBackend(backend)

	chainRules := make(map[string]*model.Rule)
	for _, r := range s.rules {
		if sameTarget(r, backend, chain) {
			chainRules[r.ID] = r
		}
	}
	if len(ids) != len(chainRules) {
		return fmt.Errorf("reorder requires all %d rule ids for chain %s", len(chainRules), chain)
	}

	posMap := make(map[string]int, len(ids))
	for i, id := range ids {
		if _, ok := chainRules[id]; !ok {
			return fmt.Errorf("rule %s does not belong to chain %s", id, chain)
		}
		posMap[id] = i + 1
	}

	for _, r := range s.rules {
		if sameTarget(r, backend, chain) {
			if pos, ok := posMap[r.ID]; ok {
				r.Position = pos
				r.UpdatedAt = time.Now()
			}
		}
	}
	return nil
}

func (s *JSONStore) ReplaceAll(rules []*model.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rules = cloneRuleSlice(rules)
	s.normalizePositionsLocked()
	return nil
}

func (s *JSONStore) All() ([]*model.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := cloneRuleSlice(s.rules)
	sortRules(result)
	return result, nil
}

func (s *JSONStore) nextPosition(backend, chain string) int {
	max := 0
	for _, r := range s.rules {
		if sameTarget(r, backend, chain) && r.Position > max {
			max = r.Position
		}
	}
	return max + 1
}

func (s *JSONStore) compactTarget(backend, chain string) {
	var chainRules []*model.Rule
	for _, r := range s.rules {
		if sameTarget(r, backend, chain) {
			chainRules = append(chainRules, r)
		}
	}
	sort.Slice(chainRules, func(i, j int) bool {
		return chainRules[i].Position < chainRules[j].Position
	})
	for i, r := range chainRules {
		r.Position = i + 1
		r.UpdatedAt = time.Now()
	}
}

func (s *JSONStore) normalizePositionsLocked() {
	targets := make(map[string][2]string)
	for _, r := range s.rules {
		r.Backend = model.NormalizeBackend(r.Backend)
		key := r.Backend + "\x00" + r.Chain
		targets[key] = [2]string{r.Backend, r.Chain}
		if r.Position < 1 {
			r.Position = 1
		}
	}
	for _, target := range targets {
		s.compactTarget(target[0], target[1])
	}
}

func sameTarget(rule *model.Rule, backend, chain string) bool {
	backend = model.NormalizeBackend(backend)
	return rule.Backend == backend && rule.Chain == chain
}

func sortRules(rules []*model.Rule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Backend != rules[j].Backend {
			return rules[i].Backend < rules[j].Backend
		}
		if rules[i].Chain != rules[j].Chain {
			return rules[i].Chain < rules[j].Chain
		}
		return rules[i].Position < rules[j].Position
	})
}

func cloneRule(rule *model.Rule) *model.Rule {
	if rule == nil {
		return nil
	}
	copy := *rule
	return &copy
}

func cloneRuleSlice(rules []*model.Rule) []*model.Rule {
	result := make([]*model.Rule, len(rules))
	for i, rule := range rules {
		result[i] = cloneRule(rule)
	}
	return result
}
