package api

import (
	"bytes"
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

func TestAllowedRemoteOperationIsExplicit(t *testing.T) {
	allowed := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/rules"},
		{http.MethodPost, "/api/v1/rules"},
		{http.MethodPut, "/api/v1/rules/reorder"},
		{http.MethodPost, "/api/v1/rules/rule-id/toggle"},
		{http.MethodGet, "/api/v1/system/chains/INPUT/rules"},
		{http.MethodPost, "/api/v1/docker/whitelist"},
	}
	for _, test := range allowed {
		if !allowedRemoteOperation(test.method, test.path) {
			t.Errorf("expected %s %s to be allowed", test.method, test.path)
		}
	}
	denied := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/users"},
		{http.MethodGet, "/api/v1/auth/session"},
		{http.MethodPost, "/api/v1/assistant/generate"},
		{http.MethodPatch, "/api/v1/rules/rule-id"},
		{http.MethodGet, "/api/v1/system/chains/../auth/session/rules"},
		{http.MethodGet, "/api/v1/rules/rule-id/extra"},
	}
	for _, test := range denied {
		if allowedRemoteOperation(test.method, test.path) {
			t.Errorf("expected %s %s to be denied", test.method, test.path)
		}
	}
}

func TestHostProxyUsesEncryptedCredentialAndCustomCA(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("sandbox does not permit local test listeners: %v", err)
	}
	remote := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "node-secret" {
			http.Error(w, "missing remote key", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/system/status" || r.URL.Query().Get("backend") != "packet" {
			http.Error(w, "unexpected target", http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Iptables-Web-Audit-Actor-B64") != "YWRtaW4" || r.Header.Get("X-Iptables-Web-Audit-Role") != "admin" || r.Header.Get("X-Iptables-Web-Audit-Remote-IP") != "192.0.2.1" {
			http.Error(w, "missing controller audit identity", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"hostname":"node-a"}}`))
	}))
	remote.Listener = listener
	remote.StartTLS()
	defer remote.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw})

	hostStore := store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", BaseURL: remote.URL, CAPEM: string(caPEM), Enabled: true}
	if err := hostStore.Create(host, "node-secret"); err != nil {
		t.Fatal(err)
	}
	handler := NewHostHandler(hostStore)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/"+host.ID+"/api/system/status?backend=packet", nil)
	req = req.WithContext(context.WithValue(req.Context(), sessionKey, &store.Session{Username: "admin", Role: "admin"}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"hostname":"node-a"`) {
		t.Fatalf("unexpected proxy body: %s", recorder.Body.String())
	}
}

func TestRemoteHostSupportsHTTPAndHTTPS(t *testing.T) {
	handler := NewHostHandler(store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "key"))
	for _, baseURL := range []string{"http://192.168.1.10:33801", "https://node.example"} {
		if _, err := handler.validatedHost(hostRequest{Name: "node", BaseURL: baseURL}, ""); err != nil {
			t.Fatalf("host URL %q rejected: %v", baseURL, err)
		}
	}
	if _, err := handler.validatedHost(hostRequest{Name: "node", BaseURL: "ftp://node.example"}, ""); err == nil {
		t.Fatal("unsupported URL scheme was accepted")
	}
}

func TestAssignedUserHasFullHostManagementAccess(t *testing.T) {
	hostStore := store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", BaseURL: "http://127.0.0.1:1", Enabled: true}
	if err := hostStore.Create(host, "node-secret"); err != nil {
		t.Fatal(err)
	}
	handler := NewHostHandler(hostStore)

	for _, remotePath := range []string{"system/backup", "system/audit", "system/rollback", "rules"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/"+host.ID+"/api/"+remotePath, nil)
		req = req.WithContext(context.WithValue(req.Context(), sessionKey, &store.Session{Username: "operator", Role: "user", HostIDs: []string{host.ID}}))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code == http.StatusForbidden || recorder.Code == http.StatusNotFound {
			t.Fatalf("assigned user was denied GET %s: status=%d body=%s", remotePath, recorder.Code, recorder.Body.String())
		}
	}
}

func TestUnassignedUserCannotEnumerateOrAccessHost(t *testing.T) {
	hostStore := store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", BaseURL: "http://127.0.0.1:1", Enabled: true}
	if err := hostStore.Create(host, "node-secret"); err != nil {
		t.Fatal(err)
	}
	handler := NewHostHandler(hostStore)
	ctx := context.WithValue(context.Background(), sessionKey, &store.Session{Username: "operator", Role: "user"})

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil).WithContext(ctx)
	listRecorder := httptest.NewRecorder()
	handler.ServeHTTP(listRecorder, listReq)
	if listRecorder.Code != http.StatusOK || strings.Contains(listRecorder.Body.String(), host.ID) {
		t.Fatalf("unassigned host leaked in list: status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/"+host.ID+"/api/rules", nil).WithContext(ctx)
	getRecorder := httptest.NewRecorder()
	handler.ServeHTTP(getRecorder, getReq)
	if getRecorder.Code != http.StatusNotFound {
		t.Fatalf("unassigned direct access status=%d, want 404; body=%s", getRecorder.Code, getRecorder.Body.String())
	}
}

func TestHostGroupAssignmentGrantsCurrentAndFutureGroupMembers(t *testing.T) {
	hostStore := store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
	first := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", Group: "Production", BaseURL: "http://127.0.0.1:1", Enabled: true}
	second := &model.ManagedHost{ID: "112233445566778899aabbcc", Name: "node-b", Group: "Production", BaseURL: "http://127.0.0.1:2", Enabled: true}
	other := &model.ManagedHost{ID: "ffeeddccbbaa998877665544", Name: "node-c", Group: "Staging", BaseURL: "http://127.0.0.1:3", Enabled: true}
	for _, host := range []*model.ManagedHost{first, second, other} {
		if err := hostStore.Create(host, "node-secret"); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewHostHandler(hostStore)
	ctx := context.WithValue(context.Background(), sessionKey, &store.Session{Username: "operator", Role: "user", HostGroups: []string{"production"}})

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil).WithContext(ctx)
	listRecorder := httptest.NewRecorder()
	handler.ServeHTTP(listRecorder, listReq)
	if listRecorder.Code != http.StatusOK || !strings.Contains(listRecorder.Body.String(), first.ID) || !strings.Contains(listRecorder.Body.String(), second.ID) || strings.Contains(listRecorder.Body.String(), other.ID) {
		t.Fatalf("group-authorized host list status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/"+second.ID+"/api/rules", nil).WithContext(ctx)
	getRecorder := httptest.NewRecorder()
	handler.ServeHTTP(getRecorder, getReq)
	if getRecorder.Code == http.StatusNotFound || getRecorder.Code == http.StatusForbidden {
		t.Fatalf("group-authorized direct access denied: status=%d body=%s", getRecorder.Code, getRecorder.Body.String())
	}
}

func TestUpdateHostResponseKeepsCredentialMetadata(t *testing.T) {
	hostStore := store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", BaseURL: "http://192.0.2.10:33801", AgentID: "aabbccddeeff001122334455", AgentPublicKey: "stable-public-key", Enabled: true}
	if err := hostStore.Create(host, "node-secret"); err != nil {
		t.Fatal(err)
	}
	handler := NewHostHandler(hostStore)
	body := bytes.NewBufferString(`{"name":"node-renamed","enabled":true}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/hosts/"+host.ID, body)
	req = req.WithContext(context.WithValue(req.Context(), sessionKey, &store.Session{Username: "admin", Role: "admin"}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"has_api_key":true`) {
		t.Fatalf("updated host response lost credential metadata: %s", recorder.Body.String())
	}
	updated, err := hostStore.Get(host.ID)
	if err != nil || updated.AgentID != host.AgentID || updated.AgentPublicKey != host.AgentPublicKey {
		t.Fatalf("update lost Agent identity: host=%#v err=%v", updated, err)
	}
}

func TestUpdateHostAddressRequiresSignedEnrollment(t *testing.T) {
	hostStore := store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", BaseURL: "http://192.0.2.10:33802", AgentID: "aabbccddeeff001122334455", Enabled: true}
	if err := hostStore.Create(host, "node-secret"); err != nil {
		t.Fatal(err)
	}
	handler := NewHostHandler(hostStore)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/hosts/"+host.ID, bytes.NewBufferString(`{"name":"node-a","base_url":"http://127.0.0.1:33802","enabled":true}`))
	req = req.WithContext(context.WithValue(req.Context(), sessionKey, &store.Session{Username: "admin", Role: "admin"}))
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "agent_enrollment_required") {
		t.Fatalf("address update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestManualHostCreationRequiresAgentEnrollment(t *testing.T) {
	handler := NewHostHandler(store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBufferString(`{}`)))
	if recorder.Code != http.StatusMethodNotAllowed || !strings.Contains(recorder.Body.String(), "agent_enrollment_required") {
		t.Fatalf("manual create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
