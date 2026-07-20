package iptables

import (
	"fmt"

	appLog "iptables-web/internal/logging"
	"iptables-web/internal/model"
)

// devBackend is a no-op backend for development when no firewall is available.
type devBackend struct {
	name   string
	chains []string
}

func newDevBackend() *devBackend {
	return &devBackend{name: "dev", chains: []string{"INPUT", "FORWARD", "OUTPUT", "DOCKER", "DOCKER_USER"}}
}

func (b *devBackend) Name() string { return b.name }

func (b *devBackend) DockerPathStatus() DockerPathStatus {
	return DockerPathStatus{Backend: b.name, ChainExists: true, ForwardJump: true, Usable: true}
}

func (b *devBackend) AddRule(rule *model.Rule) error {
	appLog.Debugf("[dev] AddRule: chain=%s action=%s dport=%s", rule.Chain, rule.Action, rule.DPort)
	return nil
}

func (b *devBackend) DeleteRule(rule *model.Rule) error {
	appLog.Debugf("[dev] DeleteRule: chain=%s action=%s", rule.Chain, rule.Action)
	return nil
}

func (b *devBackend) RuleExists(rule *model.Rule) (bool, error) { return false, nil }

func (b *devBackend) ListRules(chain string) (string, error) {
	return fmt.Sprintf(`Chain %s (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
`, chain), nil
}

func (b *devBackend) ListChains() ([]string, error) {
	return b.chains, nil
}

func (b *devBackend) FlushChain(chain string) error {
	appLog.Debugf("[dev] FlushChain: %s", chain)
	return nil
}

func (b *devBackend) Backup() (string, error) {
	return "# dev mode - no firewall backend available\n", nil
}

func (b *devBackend) ValidateRestore(data string) error {
	appLog.Debugf("[dev] ValidateRestore: %d bytes", len(data))
	return nil
}

func (b *devBackend) Restore(data string) error {
	appLog.Debugf("[dev] Restore: %d bytes", len(data))
	return nil
}
