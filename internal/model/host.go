package model

import "time"

// ManagedHost is a remote iptables-web instance registered with this
// controller. APIKeyCipher is persisted encrypted and is never serialized in
// API responses.
type ManagedHost struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Group           string     `json:"group,omitempty"`
	BaseURL         string     `json:"base_url"`
	APIKeyCipher    string     `json:"api_key_cipher,omitempty"`
	CAPEM           string     `json:"ca_pem,omitempty"`
	AgentID         string     `json:"agent_id,omitempty"`
	AgentPublicKey  string     `json:"agent_public_key,omitempty"`
	AgentLastSeenAt *time.Time `json:"agent_last_seen_at,omitempty"`
	Enabled         bool       `json:"enabled"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// ManagedHostResponse is safe to return to browsers and audit clients.
type ManagedHostResponse struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Group           string     `json:"group,omitempty"`
	BaseURL         string     `json:"base_url"`
	HasAPIKey       bool       `json:"has_api_key"`
	HasCustomCA     bool       `json:"has_custom_ca"`
	AgentID         string     `json:"agent_id,omitempty"`
	AgentLastSeenAt *time.Time `json:"agent_last_seen_at,omitempty"`
	Enabled         bool       `json:"enabled"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (h *ManagedHost) ToResponse() ManagedHostResponse {
	if h == nil {
		return ManagedHostResponse{}
	}
	return ManagedHostResponse{
		ID: h.ID, Name: h.Name, Group: h.Group, BaseURL: h.BaseURL,
		HasAPIKey: h.APIKeyCipher != "", HasCustomCA: h.CAPEM != "", AgentID: h.AgentID, AgentLastSeenAt: cloneTime(h.AgentLastSeenAt),
		Enabled: h.Enabled, CreatedAt: h.CreatedAt, UpdatedAt: h.UpdatedAt,
	}
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
