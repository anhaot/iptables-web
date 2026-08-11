// Package enrollment defines the signed, outbound Agent enrollment protocol.
// The signature proves that repeated requests come from the same Agent
// identity; administrator approval is still required before management begins.
package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const ProtocolVersion = 1

type Request struct {
	Version   int    `json:"version"`
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
	Group     string `json:"group,omitempty"`
	BaseURL   string `json:"base_url"`
	AgentKey  string `json:"agent_key,omitempty"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type signedFields struct {
	Version   int    `json:"version"`
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
	Group     string `json:"group,omitempty"`
	BaseURL   string `json:"base_url"`
	AgentKey  string `json:"agent_key,omitempty"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
}

func AgentID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:12])
}

func PublicKeyString(publicKey ed25519.PublicKey) string {
	return base64.RawStdEncoding.EncodeToString(publicKey)
}

func NewSignedRequest(privateKey ed25519.PrivateKey, name, group, baseURL, agentKey string, now time.Time) (Request, error) {
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return Request{}, fmt.Errorf("invalid Agent identity")
	}
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return Request{}, fmt.Errorf("generate enrollment nonce: %w", err)
	}
	req := Request{
		Version:   ProtocolVersion,
		AgentID:   AgentID(publicKey),
		PublicKey: PublicKeyString(publicKey),
		Name:      strings.TrimSpace(name),
		Group:     strings.TrimSpace(group),
		BaseURL:   strings.TrimSpace(baseURL),
		AgentKey:  agentKey,
		Timestamp: now.Unix(),
		Nonce:     hex.EncodeToString(nonceBytes),
	}
	canonical, err := req.canonicalBytes()
	if err != nil {
		return Request{}, err
	}
	req.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return req, nil
}

func (r Request) Verify(now time.Time, maxClockSkew time.Duration) (ed25519.PublicKey, error) {
	if r.Version != ProtocolVersion {
		return nil, fmt.Errorf("unsupported enrollment protocol version")
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(r.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Agent public key")
	}
	if r.AgentID != AgentID(ed25519.PublicKey(publicKey)) {
		return nil, fmt.Errorf("Agent ID does not match its public key")
	}
	if len(r.Nonce) != 32 {
		return nil, fmt.Errorf("invalid enrollment nonce")
	}
	if _, err := hex.DecodeString(r.Nonce); err != nil {
		return nil, fmt.Errorf("invalid enrollment nonce")
	}
	requestTime := time.Unix(r.Timestamp, 0)
	if requestTime.Before(now.Add(-maxClockSkew)) || requestTime.After(now.Add(maxClockSkew)) {
		return nil, fmt.Errorf("Agent clock differs from the controller by more than %s", maxClockSkew)
	}
	signature, err := base64.RawStdEncoding.DecodeString(r.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid enrollment signature")
	}
	canonical, err := r.canonicalBytes()
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signature) {
		return nil, fmt.Errorf("enrollment signature verification failed")
	}
	return ed25519.PublicKey(publicKey), nil
}

func (r Request) canonicalBytes() ([]byte, error) {
	return json.Marshal(signedFields{
		Version: r.Version, AgentID: r.AgentID, PublicKey: r.PublicKey,
		Name: r.Name, Group: r.Group, BaseURL: r.BaseURL, AgentKey: r.AgentKey,
		Timestamp: r.Timestamp, Nonce: r.Nonce,
	})
}
