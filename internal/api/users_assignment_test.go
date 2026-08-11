package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

func TestUserHandlerPersistsValidatedHostAssignments(t *testing.T) {
	dir := t.TempDir()
	users := store.NewUserStore(filepath.Join(dir, "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	hosts := store.NewHostStore(filepath.Join(dir, "hosts.json"), "controller-test-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", BaseURL: "http://192.0.2.10:33802", Enabled: true}
	if err := hosts.Create(host, "ipwa_test"); err != nil {
		t.Fatal(err)
	}
	handler := NewUserHandler(users, hosts)
	body := bytes.NewBufferString(`{"username":"operator","password":"secret123","role":"user","host_ids":["00112233445566778899aabb"]}`)
	recorder := httptest.NewRecorder()
	handler.CreateUser(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/users", body))
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), host.ID) {
		t.Fatalf("create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var found bool
	for _, user := range users.List() {
		if user.Username == "operator" {
			found = len(user.HostIDs) == 1 && user.HostIDs[0] == host.ID
		}
	}
	if !found {
		t.Fatal("host assignment was not persisted")
	}
}

func TestUserHandlerRejectsUnknownHostAssignment(t *testing.T) {
	dir := t.TempDir()
	users := store.NewUserStore(filepath.Join(dir, "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	hosts := store.NewHostStore(filepath.Join(dir, "hosts.json"), "controller-test-key-at-least-32-characters")
	handler := NewUserHandler(users, hosts)
	body := bytes.NewBufferString(`{"username":"operator","password":"secret123","role":"user","host_ids":["00112233445566778899aabb"]}`)
	recorder := httptest.NewRecorder()
	handler.CreateUser(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/users", body))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "不存在") {
		t.Fatalf("unknown assignment status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestUserHandlerAcceptsControllerLocalHostAssignment(t *testing.T) {
	dir := t.TempDir()
	users := store.NewUserStore(filepath.Join(dir, "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	hosts := store.NewHostStore(filepath.Join(dir, "hosts.json"), "controller-test-key-at-least-32-characters")
	handler := NewUserHandler(users, hosts)
	body := bytes.NewBufferString(`{"username":"localop","password":"secret123","role":"user","host_ids":["local"]}`)
	recorder := httptest.NewRecorder()
	handler.CreateUser(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/users", body))
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), `"host_ids":["local"]`) {
		t.Fatalf("local assignment status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestUserHandlerPersistsCanonicalHostGroupAssignments(t *testing.T) {
	dir := t.TempDir()
	users := store.NewUserStore(filepath.Join(dir, "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	hosts := store.NewHostStore(filepath.Join(dir, "hosts.json"), "controller-test-key-at-least-32-characters")
	host := &model.ManagedHost{ID: "00112233445566778899aabb", Name: "node-a", Group: "Production", BaseURL: "http://192.0.2.10:33802", Enabled: true}
	if err := hosts.Create(host, "ipwa_test"); err != nil {
		t.Fatal(err)
	}
	handler := NewUserHandler(users, hosts)
	body := bytes.NewBufferString(`{"username":"groupop","password":"secret123","role":"user","host_groups":["production"]}`)
	recorder := httptest.NewRecorder()
	handler.CreateUser(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/users", body))
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), `"host_groups":["Production"]`) {
		t.Fatalf("create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestUserHandlerRejectsUnknownHostGroupAssignment(t *testing.T) {
	dir := t.TempDir()
	users := store.NewUserStore(filepath.Join(dir, "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	hosts := store.NewHostStore(filepath.Join(dir, "hosts.json"), "controller-test-key-at-least-32-characters")
	handler := NewUserHandler(users, hosts)
	body := bytes.NewBufferString(`{"username":"groupop","password":"secret123","role":"user","host_groups":["missing"]}`)
	recorder := httptest.NewRecorder()
	handler.CreateUser(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/users", body))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "不存在") {
		t.Fatalf("unknown group status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
