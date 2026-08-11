package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"iptables-web/internal/api"
	"iptables-web/internal/enrollment"
	appLog "iptables-web/internal/logging"
)

const enrollmentInterval = 15 * time.Second

func prepareAgentEnrollment(cfg config) ([]byte, string, ed25519.PrivateKey, error) {
	if cfg.ManagerURL == "" {
		hash, err := loadAgentKeyHash(cfg.KeyHashFile)
		return hash, "", nil, err
	}
	if _, err := normalizedEnrollmentURL(cfg.ManagerURL); err != nil {
		return nil, "", nil, err
	}
	if err := validateAbsoluteHTTPURL(cfg.PublicURL, "AGENT_PUBLIC_URL"); err != nil {
		return nil, "", nil, err
	}
	identity, err := loadOrCreateIdentity(cfg.IdentityFile)
	if err != nil {
		return nil, "", nil, err
	}
	hash, err := loadAgentKeyHash(cfg.KeyHashFile)
	if err == nil {
		return hash, "", identity, nil
	}
	if !errors.Is(rootCause(err), os.ErrNotExist) {
		return nil, "", nil, err
	}
	key, hash, err := rotateAgentKey(cfg.KeyHashFile)
	return hash, key, identity, err
}

func runEnrollmentLoop(ctx context.Context, cfg config, identity ed25519.PrivateKey, initialKey string, verifier *api.AgentKeyVerifier) {
	client, endpoint, err := newEnrollmentClient(cfg)
	if err != nil {
		appLog.Errorf("Agent enrollment is disabled: %v", err)
		return
	}
	agentKey := initialKey
	lastStatus := ""
	for {
		status, err := sendEnrollment(ctx, client, endpoint, cfg, identity, agentKey)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if lastStatus != "error" {
				appLog.Errorf("Agent enrollment request failed: %v", err)
				lastStatus = "error"
			}
		} else {
			if status == "registration_required" && agentKey == "" {
				key, hash, rotateErr := rotateAgentKey(cfg.KeyHashFile)
				if rotateErr != nil {
					appLog.Errorf("Agent enrollment key rotation failed: %v", rotateErr)
				} else {
					agentKey = key
					verifier.Update(hash)
					continue
				}
			}
			if status == "approved" {
				agentKey = ""
			}
			if status != lastStatus {
				appLog.Infof("Agent enrollment status: %s", status)
				lastStatus = status
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(enrollmentInterval):
		}
	}
}

func sendEnrollment(ctx context.Context, client *http.Client, endpoint string, cfg config, identity ed25519.PrivateKey, agentKey string) (string, error) {
	reqBody, err := enrollment.NewSignedRequest(identity, cfg.AgentName, cfg.AgentGroup, cfg.PublicURL, agentKey, time.Now())
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return "", err
	}
	if len(data) > 64*1024 {
		return "", fmt.Errorf("controller response exceeds 64 KiB")
	}
	var envelope struct {
		Success bool `json:"success"`
		Data    struct {
			Status string `json:"status"`
		} `json:"data"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return "", fmt.Errorf("invalid controller response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !envelope.Success {
		message := strings.TrimSpace(envelope.Error.Message)
		if message == "" {
			message = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return "", fmt.Errorf("controller rejected enrollment: %s", message)
	}
	if envelope.Data.Status == "" {
		return "", fmt.Errorf("controller omitted enrollment status")
	}
	return envelope.Data.Status, nil
}

func newEnrollmentClient(cfg config) (*http.Client, string, error) {
	endpoint, err := normalizedEnrollmentURL(cfg.ManagerURL)
	if err != nil {
		return nil, "", err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ManagerCAFile != "" {
		pemData, err := os.ReadFile(cfg.ManagerCAFile)
		if err != nil {
			return nil, "", fmt.Errorf("read MANAGER_CA_FILE: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, "", fmt.Errorf("MANAGER_CA_FILE contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second, IdleConnTimeout: 30 * time.Second,
	}
	return &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, endpoint, nil
}

func normalizedEnrollmentURL(raw string) (string, error) {
	if err := validateAbsoluteHTTPURL(raw, "MANAGER_URL"); err != nil {
		return "", err
	}
	parsed, _ := url.Parse(raw)
	parsed.Path = "/api/v1/agent-enrollments/register"
	return parsed.String(), nil
}

func validateAbsoluteHTTPURL(raw, name string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("%s must be an absolute HTTP or HTTPS URL", name)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("%s cannot contain credentials, query, fragment or path", name)
	}
	return nil
}

func loadOrCreateIdentity(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		seed, decodeErr := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if decodeErr != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("Agent identity file is invalid")
		}
		if err := os.Chmod(path, 0600); err != nil {
			return nil, fmt.Errorf("secure Agent identity permissions: %w", err)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read Agent identity: %w", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Agent identity: %w", err)
	}
	seed := privateKey.Seed()
	if err := writePrivateFile(path, []byte(base64.RawStdEncoding.EncodeToString(seed)+"\n")); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func rotateAgentKey(path string) (string, []byte, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", nil, err
	}
	key := "ipwa_" + base64.RawURLEncoding.EncodeToString(random)
	hash := sha256.Sum256([]byte(key))
	if err := writePrivateFile(path, []byte(hex.EncodeToString(hash[:])+"\n")); err != nil {
		return "", nil, err
	}
	return key, hash[:], nil
}

func writePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".agent-secret-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

func rootCause(err error) error {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
}
