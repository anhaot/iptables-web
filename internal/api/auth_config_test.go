package api

import "testing"

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
