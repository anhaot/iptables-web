package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewAuthConfigDefaultsToEnabled(t *testing.T) {
	t.Setenv("AUTH_ENABLED", "")

	cfg := newAuthConfig(nil)
	if !cfg.enabled {
		t.Fatal("newAuthConfig().enabled = false, want true by default")
	}
}

func TestNewAuthConfigCanDisableAuthExplicitly(t *testing.T) {
	t.Setenv("AUTH_ENABLED", "false")

	cfg := newAuthConfig(nil)
	if cfg.enabled {
		t.Fatal("newAuthConfig().enabled = true, want false when AUTH_ENABLED=false")
	}
}

func TestNewAuthConfigKeepsAuthEnabledForTrue(t *testing.T) {
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("API_KEY", "secret")

	cfg := newAuthConfig(nil)
	if !cfg.enabled {
		t.Fatal("newAuthConfig().enabled = false, want true when AUTH_ENABLED=true")
	}
	if cfg.apiKey != "secret" {
		t.Fatalf("newAuthConfig().apiKey = %q, want secret", cfg.apiKey)
	}
}

func TestSessionCheckSupportsAuthDisabledMode(t *testing.T) {
	handler := &AuthHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	req = req.WithContext(context.WithValue(req.Context(), authDisabledKey, true))
	recorder := httptest.NewRecorder()
	handler.SessionCheck(recorder, req)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"auth_disabled":true`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestFrontendLandingPageMatchesAuthMode(t *testing.T) {
	if got := frontendLandingPage(true); got != "login.html" {
		t.Fatalf("auth-enabled landing page = %q", got)
	}
	if got := frontendLandingPage(false); got != "index.html" {
		t.Fatalf("auth-disabled landing page = %q", got)
	}
}
