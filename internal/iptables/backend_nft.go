package iptables

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"iptables-web/internal/model"
)

// nftBackend is retained for read-only parsing and backup compatibility.
// Runtime detection never selects it, and every mutating operation rejects the
// request. The previous implementation wrote ordinary rules into both filter
// and raw PREROUTING, which could broaden their effect and flush unrelated
// rules.
type nftBackend struct {
	bin string // "nft"
}

var nftFamilies = []string{"ip", "ip6"}

var errNativeNftWriteDisabled = fmt.Errorf("native nftables rule writes are disabled; use iptables or the iptables-nft compatibility layer")

func newNftBackend() *nftBackend {
	return &nftBackend{bin: "nft"}
}

func (b *nftBackend) Name() string { return "nftables" }

func (b *nftBackend) DockerPathStatus() DockerPathStatus {
	return DockerPathStatus{
		Backend: b.Name(),
		Message: "原生 nftables 运行后端已禁用；请使用 iptables 或 iptables-nft 兼容层",
	}
}

func (b *nftBackend) probe() error {
	if _, err := exec.LookPath(b.bin); err != nil {
		return fmt.Errorf("nft not found")
	}
	return exec.Command(b.bin, "list", "tables").Run()
}

// mapChainName translates model chain names to nftables chain names.
var nftChainMapping = map[string]string{
	"DOCKER_USER": "DOCKER-USER",
}

var nftChainReverse = map[string]string{
	"DOCKER-USER": "DOCKER_USER",
}

func nftChain(chain string) string {
	if mapped, ok := nftChainMapping[chain]; ok {
		return mapped
	}
	return chain
}

func modelChain(chain string) string {
	if mapped, ok := nftChainReverse[chain]; ok {
		return mapped
	}
	return chain
}

// AddRule rejects native nftables mutations. Rule generation in the assistant
// is independent from this runtime backend and remains available.
func (b *nftBackend) AddRule(rule *model.Rule) error {
	return errNativeNftWriteDisabled
}

// DeleteRule rejects native nftables mutations.
func (b *nftBackend) DeleteRule(rule *model.Rule) error {
	return errNativeNftWriteDisabled
}

// RuleExists checks if a matching rule exists (checks ip filter table).
func (b *nftBackend) RuleExists(rule *model.Rule) (bool, error) {
	chain := nftChain(rule.Chain)
	handle, err := b.findRuleHandle("ip", "filter", chain, rule)
	if err != nil {
		return false, err
	}
	return handle != "", nil
}

// ListRules lists rules from the ip family chain.
func (b *nftBackend) ListRules(chain string) (string, error) {
	nftName := nftChain(chain)
	cmd := exec.Command(b.bin, "-a", "list", "chain", "ip", "filter", nftName)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("nft list chain %s: %w", nftName, err)
	}
	// Use model chain name for output header
	return convertNftToIptablesFormat(chain, string(out)), nil
}

// ListChains returns all chains in the ip filter table.
func (b *nftBackend) ListChains() ([]string, error) {
	cmd := exec.Command(b.bin, "list", "table", "ip", "filter")
	out, err := cmd.Output()
	if err != nil {
		return []string{"INPUT", "FORWARD", "OUTPUT"}, nil
	}
	return parseNftChains(string(out)), nil
}

// FlushChain rejects native nftables mutations.
func (b *nftBackend) FlushChain(chain string) error {
	return errNativeNftWriteDisabled
}

// Backup dumps the full nftables ruleset.
func (b *nftBackend) Backup() (string, error) {
	cmd := exec.Command(b.bin, "list", "ruleset")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("nft list ruleset: %w", err)
	}
	return string(out), nil
}

// Restore loads rules from nftables format.
func (b *nftBackend) ValidateRestore(data string) error {
	cmd := exec.Command(b.bin, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -c -f: %w\n%s", err, string(out))
	}
	return nil
}

func (b *nftBackend) Restore(data string) error {
	return errNativeNftWriteDisabled
}

func (b *nftBackend) findAllRuleHandles(family, table, chain string, rule *model.Rule) []string {
	cmd := exec.Command(b.bin, "-a", "list", "chain", family, table, chain)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var handles []string

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !nftRuleLineMatches(line, rule) {
			continue
		}
		if strings.Contains(line, "handle ") {
			parts := strings.Split(line, "handle ")
			if len(parts) >= 2 {
				handles = append(handles, strings.TrimSpace(parts[len(parts)-1]))
			}
		}
	}
	return handles
}

func nftRuleLineMatches(line string, rule *model.Rule) bool {
	if line == "" || !strings.Contains(line, "handle ") {
		return false
	}

	ruleText := line
	if idx := strings.Index(ruleText, "# handle"); idx >= 0 {
		ruleText = strings.TrimSpace(ruleText[:idx])
	}

	action := strings.ToLower(strings.TrimSpace(rule.Action))
	if action != "" && !containsField(ruleText, action) {
		return false
	}

	proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
	if proto != "" && proto != "all" && !containsField(ruleText, proto) {
		return false
	}

	if rule.Source != "" && !strings.Contains(ruleText, "saddr "+rule.Source) {
		return false
	}
	if rule.Dest != "" && !strings.Contains(ruleText, "daddr "+rule.Dest) {
		return false
	}
	if rule.DPort != "" && !strings.Contains(ruleText, "dport "+rule.DPort) {
		return false
	}
	if rule.OriginalDPort != "" && !strings.Contains(ruleText, "ct original proto-dst "+rule.OriginalDPort) {
		return false
	}
	if rule.SPort != "" && !strings.Contains(ruleText, "sport "+rule.SPort) {
		return false
	}
	if rule.InIface != "" && !containsNftQuotedValue(ruleText, "iifname", rule.InIface) {
		return false
	}
	if rule.OutIface != "" && !containsNftQuotedValue(ruleText, "oifname", rule.OutIface) {
		return false
	}
	if rule.State != "" && !nftStateMatches(ruleText, rule.State) {
		return false
	}

	return true
}

func containsField(s, field string) bool {
	for _, f := range strings.Fields(s) {
		if f == field {
			return true
		}
	}
	return false
}

func containsNftQuotedValue(s, key, value string) bool {
	return strings.Contains(s, key+" "+value) || strings.Contains(s, key+` "`+value+`"`)
}

func nftStateMatches(s, state string) bool {
	for _, part := range strings.Split(strings.ToLower(state), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}

// Keep for backward compat
func (b *nftBackend) findRuleHandle(family, table, chain string, rule *model.Rule) (string, error) {
	handles := b.findAllRuleHandles(family, table, chain, rule)
	if len(handles) > 0 {
		return handles[0], nil
	}
	return "", nil
}

func nftFamiliesForRule(rule *model.Rule) []string {
	family := nftFamilyForAddress(rule.Source)
	if family == "" {
		family = nftFamilyForAddress(rule.Dest)
	}
	if family != "" {
		return []string{family}
	}
	return nftFamilies
}

func nftFamilyForAddress(addr string) string {
	if addr == "" {
		return ""
	}
	host := addr
	if strings.Contains(addr, "/") {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			return ""
		}
		if ip.To4() != nil {
			return "ip"
		}
		return "ip6"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "ip"
	}
	return "ip6"
}

func buildNftExpr(rule *model.Rule, family string) []string {
	var expr []string

	proto := rule.Protocol
	if proto == "" || proto == "all" {
		if rule.DPort != "" || rule.SPort != "" {
			proto = "tcp"
		}
	}

	if rule.InIface != "" {
		expr = append(expr, "iifname", rule.InIface)
	}
	if rule.OutIface != "" {
		expr = append(expr, "oifname", rule.OutIface)
	}
	if rule.Source != "" {
		expr = append(expr, family, "saddr", rule.Source)
	}
	if rule.Dest != "" {
		expr = append(expr, family, "daddr", rule.Dest)
	}

	if proto != "" && proto != "all" && rule.DPort == "" && rule.SPort == "" {
		expr = append(expr, "meta", "l4proto", proto)
	}

	if rule.State != "" {
		expr = append(expr, "ct", "state")
		expr = append(expr, nftStateExpr(rule.State)...)
	}
	if rule.DPort != "" {
		expr = append(expr, proto, "dport", rule.DPort)
	}
	if rule.SPort != "" {
		expr = append(expr, proto, "sport", rule.SPort)
	}
	if rule.OriginalDPort != "" {
		expr = append(expr, "ct", "direction", "original", "ct", "original", "proto-dst", rule.OriginalDPort)
	}
	expr = append(expr, strings.ToLower(rule.Action))
	return expr
}

func nftStateExpr(state string) []string {
	parts := strings.Split(strings.ToLower(state), ",")
	var states []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			states = append(states, part)
		}
	}
	if len(states) <= 1 {
		return states
	}
	expr := []string{"{"}
	for i, state := range states {
		if i < len(states)-1 {
			expr = append(expr, state+",")
		} else {
			expr = append(expr, state)
		}
	}
	expr = append(expr, "}")
	return expr
}

func convertNftToIptablesFormat(chain string, nftOutput string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Chain %s (policy ACCEPT 0 packets, 0 bytes)\n", chain))
	sb.WriteString("num   pkts bytes target     prot opt in     out     source               destination\n")

	num := 1
	lines := strings.Split(nftOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "table") || strings.HasPrefix(line, "chain") {
			continue
		}
		pkts := "0"
		bytes := "0"
		target := ""
		prot := ""
		source := "*"
		dest := "*"
		opts := ""

		if strings.Contains(line, "counter packets ") {
			parts := strings.Split(line, "counter packets ")
			if len(parts) > 1 {
				rest := parts[1]
				if idx := strings.Index(rest, " "); idx >= 0 {
					pkts = rest[:idx]
					rest = rest[idx+1:]
					if strings.HasPrefix(rest, "bytes ") {
						rest = rest[6:]
						if idx := strings.Index(rest, " "); idx >= 0 {
							bytes = rest[:idx]
						}
					}
				}
			}
		}

		actionLine := line
		if idx := strings.Index(actionLine, "# handle"); idx >= 0 {
			actionLine = actionLine[:idx]
		}
		fields := strings.Fields(actionLine)
		if len(fields) > 0 {
			target = strings.ToUpper(fields[len(fields)-1])
		}

		if strings.Contains(line, "tcp") {
			prot = "tcp"
		} else if strings.Contains(line, "udp") {
			prot = "udp"
		} else if strings.Contains(line, "icmp") {
			prot = "icmp"
		}

		if strings.Contains(line, "saddr ") {
			parts := strings.Split(line, "saddr ")
			if len(parts) > 1 {
				source = strings.Fields(parts[1])[0]
			}
		}
		if strings.Contains(line, "daddr ") {
			parts := strings.Split(line, "daddr ")
			if len(parts) > 1 {
				dest = strings.Fields(parts[1])[0]
			}
		}

		if strings.Contains(line, "dport ") {
			parts := strings.Split(line, "dport ")
			if len(parts) > 1 {
				opts += "dpt:" + strings.Fields(parts[1])[0] + " "
			}
		}
		if strings.Contains(line, "sport ") {
			parts := strings.Split(line, "sport ")
			if len(parts) > 1 {
				opts += "spt:" + strings.Fields(parts[1])[0] + " "
			}
		}

		sb.WriteString(fmt.Sprintf("%-5d %5s %5s %-9s %-4s %-3s %-6s %-6s %-20s %-20s %s\n",
			num, pkts, bytes, target, prot, "--", "*", "*", source, dest, strings.TrimSpace(opts)))
		num++
	}
	return sb.String()
}

func parseNftChains(output string) []string {
	var chains []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "chain ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := parts[1]
				// Reverse-map nft chain names to model names (DOCKER-USER → DOCKER_USER)
				chains = append(chains, modelChain(name))
			}
		}
	}
	if len(chains) == 0 {
		return []string{"INPUT", "FORWARD", "OUTPUT"}
	}
	return chains
}
