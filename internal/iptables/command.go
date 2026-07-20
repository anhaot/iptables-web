package iptables

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

const firewallCommandTimeout = 10 * time.Second

func commandRun(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), firewallCommandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

func commandOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), firewallCommandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func commandCombinedOutput(input, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), firewallCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	return cmd.CombinedOutput()
}
