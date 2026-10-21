package iptables

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"iptables-web/internal/model"
)

// iptablesBackend uses the iptables command (legacy or nft variant).
type iptablesBackend struct {
	bin         string
	saveBin     string
	restBin     string
	ipv6SaveBin string
	ipv6RestBin string
}

func newIptablesBackend() *iptablesBackend {
	return newIptablesBackendFor("iptables")
}

func newIptablesBackendFor(name string) *iptablesBackend {
	ipv6 := strings.Replace(name, "iptables", "ip6tables", 1)
	return &iptablesBackend{
		bin: name, saveBin: name + "-save", restBin: name + "-restore",
		ipv6SaveBin: ipv6 + "-save", ipv6RestBin: ipv6 + "-restore",
	}
}

func (b *iptablesBackend) Name() string { return b.bin }

func (b *iptablesBackend) DockerPathStatus() DockerPathStatus {
	status := DockerPathStatus{Backend: b.Name()}
	if err := commandRun(b.bin, "-w", "5", "-t", "filter", "-S", "DOCKER-USER"); err == nil {
		status.ChainExists = true
	}
	if out, err := commandOutput(b.bin, "-w", "5", "-t", "filter", "-S", "FORWARD"); err == nil {
		status.ForwardJump = forwardHasDockerUserJump(string(out))
	}
	status.Usable = status.ChainExists && status.ForwardJump
	if !status.ChainExists {
		status.Message = "未检测到 DOCKER-USER 链；Docker 可能未使用 iptables 后端，界面规则不会生效"
	} else if !status.ForwardJump {
		status.Message = "FORWARD 没有进入 DOCKER-USER；当前链中的规则不会命中 Docker 转发流量"
	}
	return status
}

func forwardHasDockerUserJump(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-A FORWARD ") && strings.Contains(line, "-j DOCKER-USER") {
			return true
		}
	}
	return false
}

func (b *iptablesBackend) probe() error {
	for _, bin := range []string{b.bin, b.saveBin, b.restBin} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("%s not found", bin)
		}
	}
	// Verify we can actually talk to the kernel
	return commandRun(b.bin, "-w", "5", "-L", "-n")
}

func (b *iptablesBackend) AddRule(rule *model.Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("refusing to add a rule without an ownership ID")
	}
	spec := buildIptablesSpec(rule)
	chain := iptablesChain(rule.Chain)
	if rule.Position > 0 {
		position := b.clampInsertPosition(chain, rule.Position)
		return b.run(append([]string{"-t", "filter", "-I", chain, fmt.Sprintf("%d", position)}, spec...)...)
	}
	return b.run(append([]string{"-t", "filter", "-A", chain}, spec...)...)
}

func (b *iptablesBackend) DeleteRule(rule *model.Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("refusing to delete a rule without an ownership ID")
	}
	ownedSpecs := [][]string{buildIptablesSpec(rule)}
	if rule.OriginalDPort != "" {
		// Older Docker rules omitted --ctdir. Their ownership comment is still
		// mandatory; an untagged lookalike is never a migration candidate.
		ownedSpecs = append(ownedSpecs, buildIptablesSpecWithDirection(rule, false))
	}
	for _, spec := range ownedSpecs {
		exists, err := b.ruleSpecExists(rule.Chain, spec)
		if err != nil {
			return err
		}
		if exists {
			if err := b.run(append([]string{"-t", "filter", "-D", iptablesChain(rule.Chain)}, spec...)...); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *iptablesBackend) RuleExists(rule *model.Rule) (bool, error) {
	return b.ruleSpecExists(rule.Chain, buildIptablesSpec(rule))
}

func (b *iptablesBackend) ruleSpecExists(chain string, spec []string) (bool, error) {
	err := b.run(append([]string{"-t", "filter", "-C", iptablesChain(chain)}, spec...)...)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b *iptablesBackend) ListRules(chain string) (string, error) {
	out, err := commandOutput(b.bin, "-w", "5", "-t", "filter", "-L", iptablesChain(chain), "-n", "-v", "--line-numbers")
	if err != nil {
		return "", fmt.Errorf("iptables -L %s: %w", chain, err)
	}
	return string(out), nil
}

func (b *iptablesBackend) ListChains() ([]string, error) {
	out, err := commandOutput(b.bin, "-w", "5", "-t", "filter", "-L", "-n")
	if err != nil {
		return nil, fmt.Errorf("iptables -L: %w", err)
	}
	return ParseChains(string(out)), nil
}

func (b *iptablesBackend) FlushChain(chain string) error {
	return b.run("-t", "filter", "-F", iptablesChain(chain))
}

func (b *iptablesBackend) Backup() (string, error) {
	out, err := commandOutput(b.saveBin)
	if err != nil {
		return "", fmt.Errorf("%s: %w", b.saveBin, err)
	}
	return string(out), nil
}

func (b *iptablesBackend) BackupIPv6() (string, error) {
	if _, err := exec.LookPath(b.ipv6SaveBin); err != nil {
		return "", fmt.Errorf("%s not found", b.ipv6SaveBin)
	}
	out, err := commandOutput(b.ipv6SaveBin)
	if err != nil {
		return "", fmt.Errorf("%s: %w", b.ipv6SaveBin, err)
	}
	return string(out), nil
}

func (b *iptablesBackend) ValidateRestore(saveData string) error {
	out, err := commandCombinedOutput(saveData, b.restBin, "--test", "--wait", "5")
	if err != nil {
		return fmt.Errorf("%s --test: %w\n%s", b.restBin, err, string(out))
	}
	return nil
}

func (b *iptablesBackend) Restore(saveData string) error {
	out, err := commandCombinedOutput(saveData, b.restBin, "--wait", "5")
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", b.restBin, err, string(out))
	}
	return nil
}

func (b *iptablesBackend) ValidateRestoreIPv6(saveData string) error {
	if _, err := exec.LookPath(b.ipv6RestBin); err != nil {
		return fmt.Errorf("%s not found", b.ipv6RestBin)
	}
	out, err := commandCombinedOutput(saveData, b.ipv6RestBin, "--test", "--wait", "5")
	if err != nil {
		return fmt.Errorf("%s --test: %w\n%s", b.ipv6RestBin, err, string(out))
	}
	return nil
}

func (b *iptablesBackend) RestoreIPv6(saveData string) error {
	if _, err := exec.LookPath(b.ipv6RestBin); err != nil {
		return fmt.Errorf("%s not found", b.ipv6RestBin)
	}
	out, err := commandCombinedOutput(saveData, b.ipv6RestBin, "--wait", "5")
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", b.ipv6RestBin, err, string(out))
	}
	return nil
}

func (b *iptablesBackend) ValidateRules(rules []*model.Rule) error {
	var input strings.Builder
	input.WriteString("*filter\n")
	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}
		input.WriteString("-A ")
		input.WriteString(iptablesChain(rule.Chain))
		input.WriteByte(' ')
		input.WriteString(strings.Join(buildIptablesSpec(rule), " "))
		input.WriteByte('\n')
	}
	input.WriteString("COMMIT\n")
	out, err := commandCombinedOutput(input.String(), b.restBin, "--test", "--noflush", "--wait", "5")
	if err != nil {
		return fmt.Errorf("preflight managed rules: %w\n%s", err, string(out))
	}
	return nil
}

func (b *iptablesBackend) run(args ...string) error {
	args = append([]string{"-w", "5"}, args...)
	ctx, cancel := context.WithTimeout(context.Background(), firewallCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", b.bin, strings.Join(args, " "), err, string(out))
	}
	return nil
}

func iptablesChain(chain string) string {
	if chain == "DOCKER_USER" {
		return "DOCKER-USER"
	}
	return chain
}

func (b *iptablesBackend) clampInsertPosition(chain string, position int) int {
	if position < 1 {
		return 1
	}
	out, err := b.ListRules(chain)
	if err != nil {
		return position
	}
	parsed, err := ParseChainOutput(out)
	if err != nil || len(parsed) == 0 {
		return position
	}
	max := len(parsed[0].Rules) + 1
	if position > max {
		return max
	}
	return position
}

func buildIptablesSpec(rule *model.Rule) []string {
	return buildIptablesSpecWithDirection(rule, true)
}

func buildIptablesSpecWithDirection(rule *model.Rule, includeOriginalDirection bool) []string {
	var spec []string
	if rule.InIface != "" {
		spec = append(spec, "-i", rule.InIface)
	}
	if rule.OutIface != "" {
		spec = append(spec, "-o", rule.OutIface)
	}
	if rule.Protocol != "" && rule.Protocol != "all" {
		spec = append(spec, "-p", rule.Protocol)
	}
	if rule.Source != "" {
		spec = append(spec, "-s", rule.Source)
	}
	if rule.Dest != "" {
		spec = append(spec, "-d", rule.Dest)
	}
	if rule.SPort != "" {
		spec = append(spec, "--sport", rule.SPort)
	}
	if rule.DPort != "" {
		spec = append(spec, "--dport", rule.DPort)
	}
	if rule.OriginalDest != "" || rule.OriginalDPort != "" {
		spec = append(spec, "-m", "conntrack")
		if rule.OriginalDest != "" {
			spec = append(spec, "--ctorigdst", rule.OriginalDest)
		}
		if rule.OriginalDPort != "" {
			spec = append(spec, "--ctorigdstport", rule.OriginalDPort)
		}
		if includeOriginalDirection {
			spec = append(spec, "--ctdir", "ORIGINAL")
		}
	}
	if rule.State != "" {
		spec = append(spec, "-m", "conntrack", "--ctstate", rule.State)
	}
	if rule.ID != "" {
		spec = append(spec, "-m", "comment", "--comment", "iptables-web:"+rule.ID)
	}
	spec = append(spec, "-j", rule.Action)
	return spec
}
