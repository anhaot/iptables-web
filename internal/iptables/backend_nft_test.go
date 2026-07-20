package iptables

import (
	"errors"
	"strings"
	"testing"

	"iptables-web/internal/model"
)

func TestNativeNftBackendMutationsAreDisabled(t *testing.T) {
	backend := newNftBackend()
	rule := &model.Rule{Chain: "INPUT", Action: "ACCEPT"}

	tests := []struct {
		name string
		err  error
	}{
		{name: "add", err: backend.AddRule(rule)},
		{name: "delete", err: backend.DeleteRule(rule)},
		{name: "flush", err: backend.FlushChain("INPUT")},
		{name: "restore", err: backend.Restore("table ip filter {}")},
	}
	for _, tt := range tests {
		if !errors.Is(tt.err, errNativeNftWriteDisabled) {
			t.Errorf("%s error = %v, want native nft write disabled", tt.name, tt.err)
		}
	}
}

func TestForcedNativeNftBackendIsRejected(t *testing.T) {
	_, err := detectForcedBackend("nftables")
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("detectForcedBackend(nftables) error = %v, want disabled error", err)
	}
}

func TestNftRuleLineMatchesFullRule(t *testing.T) {
	rule := &model.Rule{
		Action:   "DROP",
		Protocol: "tcp",
		Source:   "1.2.3.4",
		DPort:    "10089",
		InIface:  "eth0",
		State:    "NEW,ESTABLISHED",
	}

	line := `tcp iifname "eth0" ip saddr 1.2.3.4 tcp dport 10089 ct state { new, established } counter packets 0 bytes 0 drop # handle 12`
	if !nftRuleLineMatches(line, rule) {
		t.Fatalf("expected nft line to match full rule")
	}
}

func TestNftRuleLineMatchesRejectsSamePortDifferentSource(t *testing.T) {
	rule := &model.Rule{
		Action:   "DROP",
		Protocol: "tcp",
		Source:   "1.2.3.4",
		DPort:    "10089",
	}

	line := `tcp ip saddr 5.6.7.8 tcp dport 10089 counter packets 0 bytes 0 drop # handle 13`
	if nftRuleLineMatches(line, rule) {
		t.Fatalf("expected nft line with different source to be rejected")
	}
}

func TestNftRuleLineMatchesRejectsSamePortDifferentAction(t *testing.T) {
	rule := &model.Rule{
		Action:   "ACCEPT",
		Protocol: "tcp",
		DPort:    "10089",
	}

	line := `tcp dport 10089 counter packets 0 bytes 0 drop # handle 14`
	if nftRuleLineMatches(line, rule) {
		t.Fatalf("expected nft line with different action to be rejected")
	}
}

func TestNftFamiliesForRuleNarrowsIPv4Source(t *testing.T) {
	rule := &model.Rule{Source: "192.168.1.0/24"}

	got := nftFamiliesForRule(rule)
	if len(got) != 1 || got[0] != "ip" {
		t.Fatalf("nftFamiliesForRule() = %#v, want [ip]", got)
	}
}

func TestBuildNftExprUsesMetaL4ProtoWithoutPort(t *testing.T) {
	rule := &model.Rule{Protocol: "tcp", Source: "1.2.3.4", Action: "ACCEPT"}

	got := strings.Join(buildNftExpr(rule, "ip"), " ")
	want := "ip saddr 1.2.3.4 meta l4proto tcp accept"
	if got != want {
		t.Fatalf("buildNftExpr() = %q, want %q", got, want)
	}
}

func TestBuildNftExprLimitsOriginalPortToOriginalDirection(t *testing.T) {
	rule := &model.Rule{Protocol: "tcp", OriginalDPort: "18080", Action: "DROP"}
	got := strings.Join(buildNftExpr(rule, "ip"), " ")
	if !strings.Contains(got, "ct direction original ct original proto-dst 18080") {
		t.Fatalf("buildNftExpr() = %q", got)
	}
}
