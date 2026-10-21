package model

import "fmt"

// MonitoringPolicy configures controller-to-Agent checks. Agent reporting
// remains fixed at 15 seconds and is independent of the active probe cadence.
type MonitoringPolicy struct {
	ProbeIntervalSeconds int `json:"probe_interval_seconds"`
	OfflineAfterSeconds  int `json:"offline_after_seconds"`
}

func DefaultMonitoringPolicy() MonitoringPolicy {
	return MonitoringPolicy{ProbeIntervalSeconds: 60, OfflineAfterSeconds: 45}
}

func (p MonitoringPolicy) Validate() error {
	if p.ProbeIntervalSeconds < 15 || p.ProbeIntervalSeconds > 3600 {
		return fmt.Errorf("回连检测间隔必须为 15-3600 秒")
	}
	if p.OfflineAfterSeconds < 30 || p.OfflineAfterSeconds > 86400 {
		return fmt.Errorf("心跳离线阈值必须为 30-86400 秒")
	}
	return nil
}

func ValidateMonitoringOverrides(probe, offline int) error {
	p := DefaultMonitoringPolicy()
	if probe != 0 {
		p.ProbeIntervalSeconds = probe
	}
	if offline != 0 {
		p.OfflineAfterSeconds = offline
	}
	return p.Validate()
}

func (p MonitoringPolicy) ForHost(host *ManagedHost) MonitoringPolicy {
	if host != nil {
		if host.ProbeIntervalSeconds != 0 {
			p.ProbeIntervalSeconds = host.ProbeIntervalSeconds
		}
		if host.OfflineAfterSeconds != 0 {
			p.OfflineAfterSeconds = host.OfflineAfterSeconds
		}
	}
	return p
}
