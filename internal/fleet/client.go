package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"iptables-web/internal/model"
)

const maxRemoteResponseBytes = 32 * 1024 * 1024

const (
	AuditActorHeader    = "X-Iptables-Web-Audit-Actor-B64"
	AuditRoleHeader     = "X-Iptables-Web-Audit-Role"
	AuditRemoteIPHeader = "X-Iptables-Web-Audit-Remote-IP"
)

// AuditIdentity is controller-authenticated request metadata forwarded to an
// Agent after the controller has replaced the browser session with the
// per-host Agent key. Agents only trust these headers after that key verifies.
type AuditIdentity struct {
	Actor     string
	Role      string
	RemoteIP  string
	RequestID string
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

type Client struct {
	timeout time.Duration
}

func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Client{timeout: timeout}
}

func (c *Client) Do(ctx context.Context, host *model.ManagedHost, apiKey, method, remotePath, rawQuery string, body []byte, contentType string) (*Response, error) {
	return c.do(ctx, host, apiKey, method, remotePath, rawQuery, body, contentType, maxRemoteResponseBytes, AuditIdentity{})
}

func (c *Client) DoWithResponseLimit(ctx context.Context, host *model.ManagedHost, apiKey, method, remotePath, rawQuery string, body []byte, contentType string, responseLimit int64) (*Response, error) {
	return c.do(ctx, host, apiKey, method, remotePath, rawQuery, body, contentType, responseLimit, AuditIdentity{})
}

func (c *Client) DoAs(ctx context.Context, host *model.ManagedHost, apiKey, method, remotePath, rawQuery string, body []byte, contentType string, identity AuditIdentity) (*Response, error) {
	return c.do(ctx, host, apiKey, method, remotePath, rawQuery, body, contentType, maxRemoteResponseBytes, identity)
}

func (c *Client) DoWithResponseLimitAs(ctx context.Context, host *model.ManagedHost, apiKey, method, remotePath, rawQuery string, body []byte, contentType string, responseLimit int64, identity AuditIdentity) (*Response, error) {
	return c.do(ctx, host, apiKey, method, remotePath, rawQuery, body, contentType, responseLimit, identity)
}

func (c *Client) do(ctx context.Context, host *model.ManagedHost, apiKey, method, remotePath, rawQuery string, body []byte, contentType string, responseLimit int64, identity AuditIdentity) (*Response, error) {
	if host == nil || !host.Enabled {
		return nil, fmt.Errorf("remote host is disabled")
	}
	if responseLimit <= 0 || responseLimit > maxRemoteResponseBytes {
		responseLimit = maxRemoteResponseBytes
	}
	base, err := url.Parse(host.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid remote host URL: %w", err)
	}
	base.Path = strings.TrimRight(base.Path, "/") + remotePath
	base.RawQuery = rawQuery

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(host.CAPEM) != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(host.CAPEM)) {
			return nil, fmt.Errorf("remote host CA PEM contains no valid certificates")
		}
		tlsConfig.RootCAs = roots
	}
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: c.timeout,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    false,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   c.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, method, base.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	if identity.Actor != "" {
		req.Header.Set(AuditActorHeader, base64.RawURLEncoding.EncodeToString([]byte(identity.Actor)))
		req.Header.Set(AuditRoleHeader, identity.Role)
		req.Header.Set(AuditRemoteIPHeader, identity.RemoteIP)
	}
	if identity.RequestID != "" {
		req.Header.Set("X-Request-ID", identity.RequestID)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("remote request failed: %w", err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, responseLimit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read remote response: %w", err)
	}
	if int64(len(data)) > responseLimit {
		return nil, fmt.Errorf("remote response exceeds %d byte limit", responseLimit)
	}
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: data}, nil
}
