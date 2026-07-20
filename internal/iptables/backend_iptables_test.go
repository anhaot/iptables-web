package iptables

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"iptables-web/internal/model"
)

func TestWrappedExitErrorRemainsDetectableForMissingRule(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 1").Run()
	if err == nil {
		t.Fatal("command unexpectedly succeeded")
	}
	wrapped := fmt.Errorf("iptables -C: %w", err)
	var exitErr *exec.ExitError
	if !errors.As(wrapped, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("wrapped exit error was not detected: %v", wrapped)
	}
}

func TestBuildIptablesSpecDockerOriginalPort(t *testing.T) {
	rule := &model.Rule{ID: "rule-id", Protocol: "tcp", OriginalDest: "10.0.0.5", OriginalDPort: "18080", Action: "DROP"}
	got := strings.Join(buildIptablesSpec(rule), " ")
	if !strings.Contains(got, "-m conntrack --ctorigdst 10.0.0.5 --ctorigdstport 18080 --ctdir ORIGINAL") || !strings.Contains(got, "--comment iptables-web:rule-id") {
		t.Fatalf("buildIptablesSpec() = %q", got)
	}
}

func TestLegacyDockerSpecOmitsDirectionForUpgradeDeletion(t *testing.T) {
	rule := &model.Rule{Protocol: "tcp", OriginalDPort: "18080", Action: "DROP"}
	got := strings.Join(buildIptablesSpecWithDirection(rule, false), " ")
	if strings.Contains(got, "--ctdir") || !strings.Contains(got, "--ctorigdstport 18080") {
		t.Fatalf("legacy spec = %q", got)
	}
}

func TestForwardHasDockerUserJump(t *testing.T) {
	output := "-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n"
	if !forwardHasDockerUserJump(output) {
		t.Fatal("expected DOCKER-USER jump to be detected")
	}
	if forwardHasDockerUserJump("-P FORWARD DROP\n-A FORWARD -j DOCKER-FORWARD\n") {
		t.Fatal("reported a jump that is not present")
	}
}
