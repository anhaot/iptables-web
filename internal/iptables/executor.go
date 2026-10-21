package iptables

import (
	"errors"
	"fmt"
	"sort"

	"iptables-web/internal/model"
)

// Executor provides a high-level interface for managing firewall rules.
// It delegates to a detected FirewallBackend (iptables, nftables, or dev).
type Executor struct {
	backend  FirewallBackend
	backends map[string]FirewallBackend
}

// DockerPathStatus describes whether rules placed in DOCKER-USER are on the
// active Docker forwarding path. The checks are read-only.
type DockerPathStatus struct {
	Backend     string `json:"backend"`
	ChainExists bool   `json:"chain_exists"`
	ForwardJump bool   `json:"forward_jump"`
	Usable      bool   `json:"usable"`
	Message     string `json:"message,omitempty"`
}

type dockerPathInspector interface {
	DockerPathStatus() DockerPathStatus
}

func (e *Executor) DockerPathStatus() DockerPathStatus {
	backend := e.backendForID(model.BackendPacket)
	if inspector, ok := backend.(dockerPathInspector); ok {
		return inspector.DockerPathStatus()
	}
	return DockerPathStatus{Backend: e.BackendName(), Message: "当前后端无法确认 Docker 转发链是否生效"}
}

// DeleteRules only removes ownership-tagged rules. A missing owned rule must
// never cause an identically shaped external rule to be deleted instead.
func (e *Executor) DeleteRules(rules []*model.Rule) error {
	return e.DeleteOwnedRules(rules)
}

// DeleteOwnedRules removes only the comment-tagged rules created by this
// application, including rules represented by disabled records.
func (e *Executor) DeleteOwnedRules(rules []*model.Rule) error {
	var deleteErrors []error
	for _, rule := range rules {
		backend, err := e.backendForRule(rule)
		if err == nil {
			err = backend.DeleteRule(rule)
		}
		if err != nil {
			deleteErrors = append(deleteErrors, fmt.Errorf("delete owned rule %s (%s/%s): %w",
				rule.ID, model.NormalizeBackend(rule.Backend), rule.Chain, err))
		}
	}
	return errors.Join(deleteErrors...)
}

// NewExecutor detects and initializes the best available firewall backend.
func NewExecutor() (*Executor, error) {
	backends, err := DetectBackends()
	if err != nil {
		return nil, err
	}
	return &Executor{backend: backends[model.BackendPacket], backends: backends}, nil
}

// BackendName returns a compact description of all active backends.
func (e *Executor) BackendName() string {
	if backend := e.backendForID(model.BackendPacket); backend != nil {
		return backend.Name()
	}
	return ""
}

func (e *Executor) BackendNames() map[string]string {
	result := make(map[string]string)
	if backend := e.backendForID(model.BackendPacket); backend != nil {
		result[model.BackendPacket] = backend.Name()
	}
	return result
}

func (e *Executor) backendForID(id string) FirewallBackend {
	id = model.NormalizeBackend(id)
	if e.backends != nil {
		return e.backends[id]
	}
	if id == model.BackendPacket {
		return e.backend
	}
	return nil
}

func (e *Executor) backendForRule(rule *model.Rule) (FirewallBackend, error) {
	id := model.NormalizeBackend(rule.Backend)
	backend := e.backendForID(id)
	if backend == nil {
		return nil, fmt.Errorf("firewall backend %s is not available", id)
	}
	return backend, nil
}

// AddRule inserts a rule into the firewall.
func (e *Executor) AddRule(rule *model.Rule) error {
	backend, err := e.backendForRule(rule)
	if err != nil {
		return err
	}
	return backend.AddRule(rule)
}

// DeleteRule removes a rule from the firewall.
func (e *Executor) DeleteRule(rule *model.Rule) error {
	backend, err := e.backendForRule(rule)
	if err != nil {
		return err
	}
	return backend.DeleteRule(rule)
}

// RuleExists checks whether a matching rule already exists.
func (e *Executor) RuleExists(rule *model.Rule) (bool, error) {
	backend, err := e.backendForRule(rule)
	if err != nil {
		return false, err
	}
	return backend.RuleExists(rule)
}

// ListRules returns the raw listing output for a given chain.
func (e *Executor) ListRules(chain string) (string, error) {
	return e.ListRulesFor(model.BackendPacket, chain)
}

func (e *Executor) ListRulesFor(backendID, chain string) (string, error) {
	backend := e.backendForID(backendID)
	if backend == nil {
		return "", fmt.Errorf("firewall backend %s is not available", backendID)
	}
	return backend.ListRules(chain)
}

// ListChains returns all chain names.
func (e *Executor) ListChains() ([]string, error) {
	return e.ListChainsFor(model.BackendPacket)
}

func (e *Executor) ListChainsFor(backendID string) ([]string, error) {
	backend := e.backendForID(backendID)
	if backend == nil {
		return nil, fmt.Errorf("firewall backend %s is not available", backendID)
	}
	return backend.ListChains()
}

// SyncRules flushes and re-applies rules for managed chains.
func (e *Executor) SyncRules(rules []*model.Rule) error {
	rulesByTarget := make(map[string][]*model.Rule)
	for _, r := range rules {
		backendID := model.NormalizeBackend(r.Backend)
		key := backendID + "\x00" + r.Chain
		rulesByTarget[key] = append(rulesByTarget[key], r)
	}

	keys := make([]string, 0, len(rulesByTarget))
	for key := range rulesByTarget {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		chainRules := rulesByTarget[key]
		backend, err := e.backendForRule(chainRules[0])
		if err != nil {
			return err
		}
		sort.Slice(chainRules, func(i, j int) bool {
			return chainRules[i].Position < chainRules[j].Position
		})
		if validator, ok := backend.(interface{ ValidateRules([]*model.Rule) error }); ok {
			if err := validator.ValidateRules(chainRules); err != nil {
				return err
			}
		}

		for _, r := range chainRules {
			if err := backend.DeleteRule(r); err != nil {
				return fmt.Errorf("remove existing rule %s: %w", r.ID, err)
			}
		}

		effectivePosition := 1
		for _, r := range chainRules {
			if !r.Enabled {
				continue
			}
			rule := *r
			rule.Position = effectivePosition
			effectivePosition++
			if err := backend.AddRule(&rule); err != nil {
				// Best-effort reconstruction prevents a single late failure from
				// silently leaving only the prefix of the desired policy installed.
				for _, cleanup := range chainRules {
					_ = backend.DeleteRule(cleanup)
				}
				for _, restore := range chainRules {
					if !restore.Enabled {
						continue
					}
					copy := *restore
					copy.Position = restore.Position
					_ = backend.AddRule(&copy)
				}
				return fmt.Errorf("re-add rule %s: %w", r.ID, err)
			}
		}
	}
	return nil
}

// VerifyRules confirms that every enabled managed rule is present in the
// active backend. Ownership comments make this check independent of otherwise
// identical administrator-created rules.
func (e *Executor) VerifyRules(rules []*model.Rule) error {
	if e.BackendName() == "dev" {
		return nil
	}
	var missing []error
	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}
		exists, err := e.RuleExists(rule)
		if err != nil {
			missing = append(missing, fmt.Errorf("verify managed rule %s: %w", rule.ID, err))
			continue
		}
		if !exists {
			missing = append(missing, fmt.Errorf("managed rule %s is missing from %s/%s", rule.ID, model.NormalizeBackend(rule.Backend), rule.Chain))
		}
	}
	return errors.Join(missing...)
}

// Backup returns the full firewall ruleset.
func (e *Executor) Backup() (string, error) { return e.BackupFor(model.BackendPacket) }
func (e *Executor) BackupFor(backendID string) (string, error) {
	backend := e.backendForID(backendID)
	if backend == nil {
		return "", fmt.Errorf("firewall backend %s is not available", backendID)
	}
	return backend.Backup()
}

func (e *Executor) BackupIPv6() (string, error) {
	backend := e.backendForID(model.BackendPacket)
	if ipv6, ok := backend.(interface{ BackupIPv6() (string, error) }); ok {
		return ipv6.BackupIPv6()
	}
	return "", fmt.Errorf("IPv6 backup is not supported by %s", e.BackendName())
}

func (e *Executor) ValidateRestoreIPv6(data string) error {
	backend := e.backendForID(model.BackendPacket)
	if ipv6, ok := backend.(interface{ ValidateRestoreIPv6(string) error }); ok {
		return ipv6.ValidateRestoreIPv6(data)
	}
	return fmt.Errorf("IPv6 restore is not supported by %s", e.BackendName())
}

func (e *Executor) RestoreIPv6(data string) error {
	backend := e.backendForID(model.BackendPacket)
	if ipv6, ok := backend.(interface{ RestoreIPv6(string) error }); ok {
		return ipv6.RestoreIPv6(data)
	}
	return fmt.Errorf("IPv6 restore is not supported by %s", e.BackendName())
}

// ValidateRestore checks a saved firewall ruleset without applying it.
func (e *Executor) ValidateRestore(data string) error {
	return e.ValidateRestoreFor(model.BackendPacket, data)
}
func (e *Executor) ValidateRestoreFor(backendID, data string) error {
	backend := e.backendForID(backendID)
	if backend == nil {
		return fmt.Errorf("firewall backend %s is not available", backendID)
	}
	return backend.ValidateRestore(data)
}

// Restore applies a saved firewall ruleset.
func (e *Executor) Restore(data string) error { return e.RestoreFor(model.BackendPacket, data) }
func (e *Executor) RestoreFor(backendID, data string) error {
	backend := e.backendForID(backendID)
	if backend == nil {
		return fmt.Errorf("firewall backend %s is not available", backendID)
	}
	return backend.Restore(data)
}
