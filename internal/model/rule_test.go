package model

import "testing"

func TestRuleValidateRequiresTCPOrUDPForPorts(t *testing.T) {
	t.Parallel()

	rule := Rule{
		Chain:    "INPUT",
		Action:   "DROP",
		Protocol: "all",
		DPort:    "443",
		Position: 1,
	}
	if err := rule.Validate(); err == nil {
		t.Fatal("Validate() succeeded with dport and protocol=all, want error")
	}

	rule.Protocol = "tcp"
	if err := rule.Validate(); err != nil {
		t.Fatalf("Validate() with tcp dport error = %v", err)
	}
}

func TestDockerOriginalPortValidation(t *testing.T) {
	rule := Rule{Backend: BackendPacket, Chain: "DOCKER_USER", Action: "DROP", Protocol: "tcp", OriginalDPort: "18080", Position: 1}
	if err := rule.Validate(); err != nil {
		t.Fatalf("valid Docker original port rejected: %v", err)
	}
	rule.Chain = "INPUT"
	if err := rule.Validate(); err == nil {
		t.Fatal("original port accepted on INPUT")
	}
}

func TestRuleValidationCanonicalizesCIDRNetwork(t *testing.T) {
	rule := Rule{
		Backend: BackendPacket, Chain: "DOCKER_USER", Action: "ACCEPT",
		Protocol: "tcp", Source: "192.168.220.1/24", OriginalDPort: "18080", Position: 1,
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if rule.Source != "192.168.220.0/24" {
		t.Fatalf("Source = %q, want canonical network", rule.Source)
	}
}

func TestDockerOriginalPortRejectsPostDNATDPortCombination(t *testing.T) {
	rule := Rule{
		Backend: BackendPacket, Chain: "DOCKER_USER", Action: "ACCEPT",
		Protocol: "tcp", Source: "192.168.220.0/24", DPort: "18080", OriginalDPort: "18080", Position: 1,
	}
	if err := rule.Validate(); err == nil {
		t.Fatal("Validate() accepted dport together with original_dport")
	}
}

func TestRuleRejectsRemovedFirewalldBackend(t *testing.T) {
	rule := Rule{Backend: "firewalld", Chain: "INPUT", Action: "ACCEPT", Protocol: "tcp", DPort: "33801", Position: 1}
	if err := rule.Validate(); err == nil {
		t.Fatal("Validate() accepted removed firewalld backend")
	}
}

func TestManagedRuleRejectsIPv6(t *testing.T) {
	rule := Rule{Backend: BackendPacket, Chain: "INPUT", Action: "ACCEPT", Source: "2001:db8::1", Position: 1}
	if err := rule.Validate(); err == nil {
		t.Fatal("Validate() accepted IPv6 for the IPv4-only managed backend")
	}
}
