package model

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var allowedChains = map[string]bool{
	"INPUT":       true,
	"FORWARD":     true,
	"OUTPUT":      true,
	"DOCKER":      true,
	"DOCKER_USER": true,
}

var allowedActions = map[string]bool{
	"ACCEPT": true,
	"DROP":   true,
	"REJECT": true,
	"LOG":    true,
	"RETURN": true,
}

var allowedProtocols = map[string]bool{
	"tcp":  true,
	"udp":  true,
	"icmp": true,
	"all":  true,
	"":     true,
}

var allowedStates = map[string]bool{
	"":                        true,
	"NEW":                     true,
	"ESTABLISHED":             true,
	"RELATED":                 true,
	"INVALID":                 true,
	"NEW,ESTABLISHED":         true,
	"NEW,RELATED":             true,
	"ESTABLISHED,RELATED":     true,
	"NEW,ESTABLISHED,RELATED": true,
}

var validInterface = regexp.MustCompile(`^[a-zA-Z0-9_.\-*+@]*$`)

const (
	BackendPacket = "packet"
)

type Rule struct {
	ID            string    `json:"id"`
	Backend       string    `json:"backend"`
	Chain         string    `json:"chain"`
	Action        string    `json:"action"`
	Protocol      string    `json:"protocol,omitempty"`
	Source        string    `json:"source,omitempty"`
	Dest          string    `json:"dest,omitempty"`
	DPort         string    `json:"dport,omitempty"`
	OriginalDest  string    `json:"original_dest,omitempty"`
	OriginalDPort string    `json:"original_dport,omitempty"`
	SPort         string    `json:"sport,omitempty"`
	InIface       string    `json:"in_iface,omitempty"`
	OutIface      string    `json:"out_iface,omitempty"`
	State         string    `json:"state,omitempty"`
	Position      int       `json:"position"`
	Enabled       bool      `json:"enabled"`
	Desc          string    `json:"desc,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func NormalizeBackend(backend string) string {
	backend = strings.ToLower(strings.TrimSpace(backend))
	if backend == "" || backend == "iptables" || backend == "nft" || backend == "nftables" {
		return BackendPacket
	}
	return backend
}

func (r *Rule) Validate() error {
	r.Backend = NormalizeBackend(r.Backend)
	if r.Backend != BackendPacket {
		return fmt.Errorf("invalid backend %q: only packet (iptables/iptables-nft) is supported", r.Backend)
	}

	r.Chain = strings.ToUpper(strings.TrimSpace(r.Chain))
	if !allowedChains[r.Chain] {
		return fmt.Errorf("invalid chain %q: must be one of INPUT, FORWARD, OUTPUT, DOCKER, DOCKER_USER", r.Chain)
	}

	r.Action = strings.ToUpper(strings.TrimSpace(r.Action))
	if !allowedActions[r.Action] {
		return fmt.Errorf("invalid action %q: must be one of ACCEPT, DROP, REJECT, LOG, RETURN", r.Action)
	}

	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	if !allowedProtocols[r.Protocol] {
		return fmt.Errorf("invalid protocol %q: must be one of tcp, udp, icmp, all", r.Protocol)
	}

	if r.Source != "" {
		normalized, err := normalizeIPv4OrCIDR(r.Source)
		if err != nil {
			return fmt.Errorf("invalid source: %w", err)
		}
		r.Source = normalized
	}

	if r.Dest != "" {
		normalized, err := normalizeIPv4OrCIDR(r.Dest)
		if err != nil {
			return fmt.Errorf("invalid destination: %w", err)
		}
		r.Dest = normalized
	}

	if r.DPort != "" {
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("dport requires tcp or udp protocol")
		}
		if err := validatePortRange(r.DPort); err != nil {
			return fmt.Errorf("invalid dport: %w", err)
		}
	}
	if r.OriginalDPort != "" {
		if r.Chain != "FORWARD" && r.Chain != "DOCKER_USER" {
			return fmt.Errorf("original_dport is only valid in FORWARD or DOCKER_USER")
		}
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("original_dport requires tcp or udp protocol")
		}
		if err := validatePortRange(r.OriginalDPort); err != nil {
			return fmt.Errorf("invalid original_dport: %w", err)
		}
		if r.DPort != "" {
			return fmt.Errorf("dport cannot be combined with original_dport: Docker traffic is already DNATed; leave dport empty")
		}
	}
	if r.OriginalDest != "" {
		if r.Chain != "FORWARD" && r.Chain != "DOCKER_USER" {
			return fmt.Errorf("original_dest is only valid in FORWARD or DOCKER_USER")
		}
		normalized, err := normalizeIPv4OrCIDR(r.OriginalDest)
		if err != nil {
			return fmt.Errorf("invalid original destination: %w", err)
		}
		r.OriginalDest = normalized
	}

	if r.SPort != "" {
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("sport requires tcp or udp protocol")
		}
		if err := validatePortRange(r.SPort); err != nil {
			return fmt.Errorf("invalid sport: %w", err)
		}
	}

	if r.InIface != "" && !validInterface.MatchString(r.InIface) {
		return fmt.Errorf("invalid input interface name %q", r.InIface)
	}

	if r.OutIface != "" && !validInterface.MatchString(r.OutIface) {
		return fmt.Errorf("invalid output interface name %q", r.OutIface)
	}

	r.State = strings.ToUpper(strings.TrimSpace(r.State))
	if !allowedStates[r.State] {
		return fmt.Errorf("invalid state %q: must be one of NEW, ESTABLISHED, RELATED, INVALID or comma-separated combinations", r.State)
	}

	if r.Position < 1 {
		return fmt.Errorf("position must be >= 1, got %d", r.Position)
	}

	if len(r.Desc) > 255 {
		return fmt.Errorf("description too long (max 255 chars)")
	}

	return nil
}

func normalizeIPv4OrCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		ip, network, err := net.ParseCIDR(s)
		if err != nil {
			return "", err
		}
		if ip.To4() == nil {
			return "", fmt.Errorf("IPv6 managed rules are not supported; use the rule assistant for ip6tables")
		}
		return network.String(), nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("invalid IP or CIDR %q", s)
	}
	if ip.To4() == nil {
		return "", fmt.Errorf("IPv6 managed rules are not supported; use the rule assistant for ip6tables")
	}
	return ip.To4().String(), nil
}

func validatePortRange(s string) error {
	parts := strings.Split(s, ":")
	if len(parts) > 2 {
		return fmt.Errorf("invalid port range %q: use single port or range like 80:443", s)
	}
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid port %q: must be 1-65535", p)
		}
	}
	if len(parts) == 2 {
		a, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
		b, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
		if a > b {
			return fmt.Errorf("invalid port range: start > end")
		}
	}
	return nil
}
