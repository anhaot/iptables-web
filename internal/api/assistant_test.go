package api

import (
	"strings"
	"testing"
)

func normalizedRequest(t *testing.T, req GenerateRequest) GenerateRequest {
	t.Helper()
	if req.Chain == "" {
		req.Chain = "INPUT"
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if err := normalizeAndValidateGenerateRequest(&req); err != nil {
		t.Fatalf("normalizeAndValidateGenerateRequest() error = %v", err)
	}
	return req
}

func commandByLabel(t *testing.T, commands []CommandVariant, label string) string {
	t.Helper()
	for _, command := range commands {
		if command.Label == label {
			return command.Command
		}
	}
	t.Fatalf("missing %s command in %#v", label, commands)
	return ""
}

func TestGenerateAllowIPPortPreservesWhitelistOrder(t *testing.T) {
	req := normalizedRequest(t, GenerateRequest{
		Scenario: "allow_ip_port", Backend: "all", Family: "ipv4",
		Source: "10.0.0.0/8", Port: "3306", Protocol: "tcp",
	})
	commands, _ := buildCommands(req)
	iptablesCommand := commandByLabel(t, commands, "iptables")
	lines := strings.Split(iptablesCommand, "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "-I INPUT 1") || !strings.Contains(lines[0], "-s 10.0.0.0/8") || !strings.Contains(lines[0], "-j ACCEPT") {
		t.Fatalf("whitelist command order = %q", iptablesCommand)
	}
	if !strings.Contains(lines[1], "-I INPUT 2") || !strings.Contains(lines[1], "-j DROP") {
		t.Fatalf("fallback command order = %q", iptablesCommand)
	}
	if len(commands) != 3 {
		t.Fatalf("expected iptables, nftables and firewalld variants, got %#v", commands)
	}
	firewalldCommand := commandByLabel(t, commands, "firewalld")
	if !strings.Contains(firewalldCommand, `priority="-100"`) || !strings.Contains(firewalldCommand, `priority="-90"`) {
		t.Fatalf("firewalld whitelist priority = %q", firewalldCommand)
	}
}

func TestGenerateRestrictPortUsesSourceNegationBeforeAction(t *testing.T) {
	req := normalizedRequest(t, GenerateRequest{
		Scenario: "restrict_port", Backend: "all", Family: "ipv4",
		Source: "172.16.0.0/12", Port: "5432", Protocol: "tcp",
	})
	commands, _ := buildCommands(req)
	iptablesCommand := commandByLabel(t, commands, "iptables")
	if !strings.Contains(iptablesCommand, "! -s 172.16.0.0/12") || strings.Contains(iptablesCommand, "-d !") {
		t.Fatalf("invalid iptables negation: %q", iptablesCommand)
	}
	nftCommand := commandByLabel(t, commands, "nftables")
	sourceIndex := strings.Index(nftCommand, "ip saddr != 172.16.0.0/12")
	actionIndex := strings.LastIndex(nftCommand, " drop")
	if sourceIndex < 0 || actionIndex < 0 || sourceIndex > actionIndex {
		t.Fatalf("invalid nftables expression order: %q", nftCommand)
	}
}

func TestGenerateNormalizesRangesChainsAndIPv6(t *testing.T) {
	req := normalizedRequest(t, GenerateRequest{
		Scenario: "block_port", Backend: "all", Chain: "DOCKER-USER", Family: "ipv6",
		Port: "8000:9000", Protocol: "tcp",
	})
	commands, warnings := buildCommands(req)
	iptablesCommand := commandByLabel(t, commands, "iptables")
	if !strings.Contains(iptablesCommand, "ip6tables -I DOCKER-USER 1") || !strings.Contains(iptablesCommand, "--ctorigdstport 8000:9000 --ctdir ORIGINAL") {
		t.Fatalf("unexpected ip6tables command: %q", iptablesCommand)
	}
	nftCommand := commandByLabel(t, commands, "nftables")
	if !strings.Contains(nftCommand, "nft add rule ip6 filter DOCKER-USER") || !strings.Contains(nftCommand, "ct direction original ct original proto-dst 8000-9000") {
		t.Fatalf("unexpected nft command: %q", nftCommand)
	}
	if len(warnings) == 0 {
		t.Fatal("expected Docker original-port warning")
	}
}

func TestGenerateValidationRejectsUnsafeOrAmbiguousInputs(t *testing.T) {
	tests := []GenerateRequest{
		{Scenario: "block_port", Backend: "iptables", Chain: "INPUT;rm", Protocol: "tcp", Port: "80"},
		{Scenario: "block_port", Backend: "iptables", Chain: "INPUT", Protocol: "all", Port: "80"},
		{Scenario: "allow_ip", Backend: "iptables", Chain: "INPUT", Protocol: "tcp", Source: "10.0.0.0/8;echo"},
		{Scenario: "block_port", Backend: "firewalld", Chain: "FORWARD", Protocol: "tcp", Port: "80"},
		{Scenario: "block_port", Backend: "firewalld", Chain: "INPUT", Zone: "public;rm", Protocol: "tcp", Port: "80"},
		{Scenario: "allow_ip", Backend: "iptables", Chain: "DOCKER_USER", Protocol: "tcp", Source: "10.0.0.0/8"},
	}
	for _, req := range tests {
		if err := normalizeAndValidateGenerateRequest(&req); err == nil {
			t.Fatalf("unsafe request accepted: %#v", req)
		}
	}
}

func TestExplainFirewalldRichRule(t *testing.T) {
	explanation, warnings := explainCommand(`firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port port="33801" protocol="tcp" accept'`)
	for _, want := range []string{"**类型**: firewalld 命令", "**Zone**: `public`", "**来源地址**: `10.0.0.0/8`", "**目标端口**: `33801`"} {
		if !strings.Contains(explanation, want) {
			t.Fatalf("explanation %q missing %q", explanation, want)
		}
	}
	if !strings.Contains(strings.Join(warnings, " "), "firewall-cmd --reload") {
		t.Fatalf("missing permanent reload warning: %#v", warnings)
	}
}

func TestExplainFirewalldPortCommand(t *testing.T) {
	explanation, _ := explainCommand("firewall-cmd --permanent --zone=public --add-port=33801/tcp")
	if !strings.Contains(explanation, "放行端口 `33801/tcp`") {
		t.Fatalf("firewalld port explanation = %q", explanation)
	}
}

func TestExplainMultipleCommandsWarnsAboutImplicitInsertReversal(t *testing.T) {
	explanation, warnings := explainCommand("iptables -I INPUT -s 10.0.0.0/8 -j ACCEPT\niptables -I INPUT -j DROP")
	if !strings.Contains(explanation, "### 命令 1") || !strings.Contains(explanation, "### 命令 2") {
		t.Fatalf("multi-command explanation = %q", explanation)
	}
	if !strings.Contains(strings.Join(warnings, " "), "最终顺序与文本顺序相反") {
		t.Fatalf("missing insert-order warning: %#v", warnings)
	}
}

func TestExplainDockerRuleWarnsAboutHostPortUsedAsDPort(t *testing.T) {
	_, warnings := explainCommand("iptables -I DOCKER-USER -p tcp --dport 18080 -m conntrack --ctorigdstport 18080 -j ACCEPT")
	if !strings.Contains(strings.Join(warnings, " "), "DNAT 后的容器端口") {
		t.Fatalf("missing post-DNAT dport warning: %#v", warnings)
	}
}

func TestExplainDockerDropWarnsWhenOriginalDirectionIsMissing(t *testing.T) {
	_, warnings := explainCommand("iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 18080 -j DROP")
	if !strings.Contains(strings.Join(warnings, " "), "返回包") {
		t.Fatalf("missing return-direction warning: %#v", warnings)
	}
	explanation, warnings := explainCommand("iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 18080 --ctdir ORIGINAL -j DROP")
	if !strings.Contains(explanation, "**连接方向**: `ORIGINAL`") || strings.Contains(strings.Join(warnings, " "), "返回包") {
		t.Fatalf("directional explanation=%q warnings=%#v", explanation, warnings)
	}
}

func TestExplainNftCommandReportsFamilyTableAndChain(t *testing.T) {
	explanation, _ := explainCommand("nft add rule ip filter INPUT ip saddr 10.0.0.0/8 tcp dport 443 accept")
	for _, want := range []string{"**地址族**: `ip`", "**目标表**: `filter`", "**目标链**: `INPUT`", "**目标端口**: `443`"} {
		if !strings.Contains(explanation, want) {
			t.Fatalf("explanation %q missing %q", explanation, want)
		}
	}
}
