package iptables

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func TestExplicitBackendUsesMatchingCommandFamily(t *testing.T) {
	for _, name := range []string{"iptables", "iptables-nft", "iptables-legacy"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			logPath := filepath.Join(dir, "commands.log")
			t.Setenv("COMMAND_LOG", logPath)
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			ipv6 := strings.Replace(name, "iptables", "ip6tables", 1)
			names := []string{name, name + "-save", name + "-restore", ipv6 + "-save", ipv6 + "-restore"}
			for _, bin := range names {
				if err := os.WriteFile(filepath.Join(dir, bin), []byte("#!/bin/sh\nprintf '%s %s\\n' \"${0##*/}\" \"$*\" >> \"$COMMAND_LOG\"\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if name != "iptables" {
				// Falling back to alternatives would silently manage another ruleset.
				if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			backend, err := detectForcedBackend(name)
			if err != nil {
				t.Fatal(err)
			}
			b := backend.(*iptablesBackend)
			if b.Name() != name {
				t.Fatalf("backend name = %s, want %s", b.Name(), name)
			}
			if _, err := b.Backup(); err != nil {
				t.Fatal(err)
			}
			if err := b.ValidateRestore("*filter\nCOMMIT\n"); err != nil {
				t.Fatal(err)
			}
			if err := b.Restore("*filter\nCOMMIT\n"); err != nil {
				t.Fatal(err)
			}
			if _, err := b.BackupIPv6(); err != nil {
				t.Fatal(err)
			}
			if err := b.ValidateRestoreIPv6("*filter\nCOMMIT\n"); err != nil {
				t.Fatal(err)
			}
			if err := b.RestoreIPv6("*filter\nCOMMIT\n"); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, bin := range names {
				if !strings.Contains(string(data), bin+" ") {
					t.Errorf("%s was never executed: %s", bin, data)
				}
			}
		})
	}
}

func TestRuleMutationRequiresOwnershipID(t *testing.T) {
	b := newIptablesBackend()
	rule := &model.Rule{Chain: "INPUT", Action: "DROP"}
	if err := b.AddRule(rule); err == nil {
		t.Fatal("untagged add accepted")
	}
	if err := b.DeleteRule(rule); err == nil {
		t.Fatal("untagged delete accepted")
	}
}
