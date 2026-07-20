package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"iptables-web/internal/iptables"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

func TestRemoteRequestIP(t *testing.T) {
	if got := remoteRequestIP("192.168.220.1:54321"); got != "192.168.220.1" {
		t.Fatalf("IPv4 remote = %q", got)
	}
	if got := remoteRequestIP("[2001:db8::1]:54321"); got != "2001:db8::1" {
		t.Fatalf("IPv6 remote = %q", got)
	}
}

func TestCreateDockerWhitelistDoesNotReuseDisabledRulesAndScopesHostIP(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	s := store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	for _, rule := range []*model.Rule{
		{ID: "disabled-allow", Backend: model.BackendPacket, Chain: "DOCKER_USER", Action: "ACCEPT", Protocol: "tcp", Source: "192.0.2.1", OriginalDest: "10.0.0.5", OriginalDPort: "18080", Position: 1, Enabled: false},
		{ID: "disabled-drop", Backend: model.BackendPacket, Chain: "DOCKER_USER", Action: "DROP", Protocol: "tcp", OriginalDest: "10.0.0.5", OriginalDPort: "18080", Position: 2, Enabled: false},
	} {
		if err := s.Create(rule); err != nil {
			t.Fatal(err)
		}
	}
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(s, executor)
	body := `{"source":"192.0.2.1","protocol":"tcp","host_ip":"10.0.0.5","host_port":18080,"container_name":"nginx","container_port":80}`
	recorder := httptest.NewRecorder()
	handler.CreateDockerWhitelist(recorder, httptest.NewRequest("POST", "/api/v1/docker/whitelist", strings.NewReader(body)))
	if recorder.Code != 201 {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	rules, _ := s.ListByTarget(model.BackendPacket, "DOCKER_USER")
	enabled := 0
	for _, rule := range rules {
		if rule.Enabled {
			enabled++
			if rule.OriginalDest != "10.0.0.5" {
				t.Fatalf("enabled rule not scoped to host IP: %#v", rule)
			}
		}
	}
	if enabled != 2 {
		t.Fatalf("enabled rules=%d, want new ACCEPT and DROP; rules=%#v", enabled, rules)
	}
}

func TestCreateDockerWhitelistIsAtomicAndUsesCorrectDirection(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	s := store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json"))
	executor, err := iptables.NewExecutor()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(s, executor)
	body := `{
		"source":"192.168.220.1/24",
		"protocol":"tcp",
		"host_ip":"0.0.0.0",
		"host_port":18080,
		"container_name":"nginx",
		"container_port":80
	}`
	recorder := httptest.NewRecorder()
	handler.CreateDockerWhitelist(recorder, httptest.NewRequest("POST", "/api/v1/docker/whitelist", strings.NewReader(body)))
	if recorder.Code != 201 {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	rules, err := s.ListByTarget("packet", "DOCKER_USER")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %#v, want ACCEPT and DROP", rules)
	}
	if rules[0].Action != "ACCEPT" || rules[0].Source != "192.168.220.0/24" || rules[0].Position != 1 {
		t.Fatalf("allow rule = %#v", rules[0])
	}
	if rules[1].Action != "DROP" || rules[1].Position != 2 {
		t.Fatalf("drop rule = %#v", rules[1])
	}
	if rules[0].Desc != "允许 192.168.220.0/24 访问 宿主机:18080 → nginx:80" {
		t.Fatalf("allow description = %q", rules[0].Desc)
	}

	var response struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || !response.Success {
		t.Fatalf("response = %s, error = %v", recorder.Body.String(), err)
	}
}
