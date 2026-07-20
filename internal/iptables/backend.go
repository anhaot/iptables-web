package iptables

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	appLog "iptables-web/internal/logging"
	"iptables-web/internal/model"
)

// FirewallBackend abstracts firewall rule operations across different backends.
type FirewallBackend interface {
	Name() string
	AddRule(rule *model.Rule) error
	DeleteRule(rule *model.Rule) error
	RuleExists(rule *model.Rule) (bool, error)
	ListRules(chain string) (string, error)
	ListChains() ([]string, error)
	FlushChain(chain string) error
	Backup() (string, error)
	ValidateRestore(data string) error
	Restore(data string) error
}

// DetectBackend returns the supported packet-filter backend. Native nftables
// writes are intentionally disabled; iptables may itself use the nft
// compatibility layer (iptables-nft).
func DetectBackend() (FirewallBackend, error) {
	backends, err := DetectBackends()
	if err != nil {
		return nil, err
	}
	if backend := backends[model.BackendPacket]; backend != nil {
		return backend, nil
	}
	return nil, fmt.Errorf("未检测到可用的防火墙后端")
}

// DetectBackends discovers exactly one packet-filter backend. firewalld is not
// managed by this application; administrators keep using it outside the app.
func DetectBackends() (map[string]FirewallBackend, error) {
	devMode := os.Getenv("DEV_MODE") == "true"
	if devMode {
		appLog.Infof("[firewall] DEV_MODE=true — using no-op backend")
		return map[string]FirewallBackend{model.BackendPacket: newDevBackend()}, nil
	}

	result := make(map[string]FirewallBackend)
	forced := strings.ToLower(strings.TrimSpace(os.Getenv("FIREWALL_BACKEND")))
	if forced == "dev" {
		return map[string]FirewallBackend{model.BackendPacket: newDevBackend()}, nil
	}

	if forced != "" && forced != "auto" {
		backend, err := detectForcedBackend(forced)
		if err != nil {
			return nil, err
		}
		result[model.BackendPacket] = backend
	} else if backend := detectPacketBackend(); backend != nil {
		result[model.BackendPacket] = backend
	}

	if len(result) > 0 {
		return result, nil
	}

	return nil, fmt.Errorf(
		"未检测到可用的 iptables 后端。原生 nftables 写入因安全原因已禁用；iptables-nft 兼容层可以使用。请安装 iptables：\n" +
			"  Ubuntu/Debian/Kylin: apt install iptables\n" +
			"  CentOS/RHEL:         yum install iptables-services\n" +
			"  开发模式:             DEV_MODE=true 跳过防火墙操作")
}

func detectPacketBackend() FirewallBackend {
	// Docker installs and programs iptables chains even when iptables uses the
	// nft compatibility layer, so prefer it for Docker-facing rules.
	if _, err := exec.LookPath("iptables"); err == nil {
		backend := newIptablesBackend()
		if err := backend.probe(); err == nil {
			ver, _ := commandOutput("iptables", "--version")
			appLog.Infof("[firewall] detected packet backend: iptables (%s)", strings.TrimSpace(string(ver)))
			return backend
		} else {
			appLog.Warnf("[firewall] iptables probe failed: %v", err)
		}
	}
	return nil
}

func detectForcedBackend(name string) (FirewallBackend, error) {
	switch name {
	case "nft", "nftables":
		return nil, fmt.Errorf("FIREWALL_BACKEND=%s is disabled: native nftables rule writes are unsafe; use iptables or the iptables-nft compatibility layer", name)
	case "iptables", "iptables-legacy", "iptables-nft":
		backend := newIptablesBackend()
		if err := backend.probe(); err != nil {
			return nil, fmt.Errorf("FIREWALL_BACKEND=%s requested but iptables is unavailable: %w", name, err)
		}
		appLog.Infof("[firewall] forced backend: iptables")
		return backend, nil
	case "dev":
		appLog.Infof("[firewall] forced backend: dev")
		return newDevBackend(), nil
	default:
		return nil, fmt.Errorf("unsupported FIREWALL_BACKEND %q (use auto, iptables, or dev)", name)
	}
}
