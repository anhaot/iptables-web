package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"iptables-web/internal/store"
)

func TestAuthPolicyIsReadableWithoutExposingUserData(t *testing.T) {
	users := store.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	handler := NewAuthHandler(users)
	recorder := httptest.NewRecorder()
	handler.GetPolicy(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/auth/policy", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"case_sensitive":false`) || !strings.Contains(recorder.Body.String(), `"min_length":1`) || strings.Contains(recorder.Body.String(), "password_history") || strings.Contains(recorder.Body.String(), "default_reset_password") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAdminSecurityPolicyDoesNotExposeDefaultPasswordHash(t *testing.T) {
	users := store.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	handler := NewUserHandler(users)
	body := `{"password":{"min_length":8,"min_uppercase":0,"min_lowercase":1,"min_digits":1,"min_special":0,"history_count":5,"min_changed_characters":3},"captcha":{"case_sensitive":true},"login":{"max_failures":4,"lockout_mode":"administrator","lockout_minutes":15,"password_max_age_days":90,"default_reset_password":"Default123"}}`
	recorder := httptest.NewRecorder()
	handler.UpdateSecurityPolicy(recorder, httptest.NewRequest(http.MethodPut, "/api/v1/security-policy", strings.NewReader(body)))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"default_reset_password_configured":true`) || strings.Contains(recorder.Body.String(), "default_reset_password_hash") || strings.Contains(recorder.Body.String(), "Default123") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSecurityPolicyUpdateValidatesAndPersists(t *testing.T) {
	dir := t.TempDir()
	users := store.NewUserStore(filepath.Join(dir, "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	handler := NewUserHandler(users)
	body := `{"password":{"min_length":12,"min_uppercase":1,"min_lowercase":1,"min_digits":1,"min_special":1,"history_count":8,"min_changed_characters":5},"captcha":{"case_sensitive":false}}`
	recorder := httptest.NewRecorder()
	handler.UpdateSecurityPolicy(recorder, httptest.NewRequest(http.MethodPut, "/api/v1/security-policy", strings.NewReader(body)))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"min_length":12`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	reloaded := store.NewUserStore(filepath.Join(dir, "users.json"))
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	policy := reloaded.SecurityPolicy()
	if policy.Password.MinLength != 12 || policy.Captcha.CaseSensitive {
		t.Fatalf("reloaded policy = %#v", policy)
	}
}

func TestSecurityPolicyRejectsImpossibleRequirements(t *testing.T) {
	users := store.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	handler := NewUserHandler(users)
	body := `{"password":{"min_length":6,"min_uppercase":4,"min_lowercase":4,"min_digits":4,"min_special":4,"history_count":5,"min_changed_characters":3},"captcha":{"case_sensitive":true}}`
	recorder := httptest.NewRecorder()
	handler.UpdateSecurityPolicy(recorder, httptest.NewRequest(http.MethodPut, "/api/v1/security-policy", strings.NewReader(body)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
