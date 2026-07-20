package model

// ParsedRule represents a live iptables rule parsed from iptables -L output.
type ParsedRule struct {
	Num     int    `json:"num"`
	Pkts    int64  `json:"pkts"`
	Bytes   int64  `json:"bytes"`
	Target  string `json:"target"`
	Prot    string `json:"prot"`
	Opt     string `json:"opt"`
	In      string `json:"in"`
	Out     string `json:"out"`
	Source  string `json:"source"`
	Dest    string `json:"dest"`
	Options string `json:"options"`
}

// ChainInfo holds metadata and rules for a single iptables chain.
type ChainInfo struct {
	Backend     string       `json:"backend,omitempty"`
	Name        string       `json:"name"`
	Policy      string       `json:"policy"`
	PacketCount int64        `json:"packet_count"`
	ByteCount   int64        `json:"byte_count"`
	Rules       []ParsedRule `json:"rules"`
}

// DockerMapping represents a Docker container port mapping.
type DockerMapping struct {
	ContainerName string `json:"container_name"`
	ContainerID   string `json:"container_id"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"host_ip"`
	Family        string `json:"family"`
}

// SystemInfo provides system-level information.
type SystemInfo struct {
	FirewallBackend  string                `json:"firewall_backend"`
	FirewallVersion  string                `json:"firewall_version"`
	FirewallBackends []FirewallBackendInfo `json:"firewall_backends"`
	KernelVersion    string                `json:"kernel_version"`
	Hostname         string                `json:"hostname"`
	ManagedChains    int                   `json:"managed_chains"`
	TotalRules       int                   `json:"total_rules"`
	EnabledRules     int                   `json:"enabled_rules"`
}

type FirewallBackendInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// ReorderRequest is the body for reordering rules in a chain.
type ReorderRequest struct {
	Backend string   `json:"backend"`
	Chain   string   `json:"chain"`
	RuleIDs []string `json:"rule_ids"`
}
