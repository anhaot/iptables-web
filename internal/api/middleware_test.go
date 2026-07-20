package api

import (
	"testing"
	"time"
)

func TestShouldSkipRateLimitForStaticAndHealth(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/", "/login.html", "/favicon.ico", "/css/base.css", "/js/app.js", "/api/v1/health"} {
		if !shouldSkipRateLimit(path) {
			t.Fatalf("shouldSkipRateLimit(%q) = false, want true", path)
		}
	}
}

func TestRateLimiterResetsByWindowStartNotLastRejectedAttempt(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)
	if !rl.allow("client") || rl.allow("client") {
		t.Fatal("unexpected initial rate-limit behavior")
	}
	rl.mu.Lock()
	rl.visitors["client"].windowStart = time.Now().Add(-time.Minute)
	rl.visitors["client"].lastSeen = time.Now()
	rl.mu.Unlock()
	if !rl.allow("client") {
		t.Fatal("rate limit did not reset after the fixed window elapsed")
	}
}

func TestShouldRateLimitAPI(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/api/v1/rules", "/api/v1/auth/login", "/api/v1/auth/captcha"} {
		if shouldSkipRateLimit(path) {
			t.Fatalf("shouldSkipRateLimit(%q) = true, want false", path)
		}
	}
}

func TestAuthPublicPathsAllowFrontendShell(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/", "/index.html", "/login.html", "/css/base.css", "/js/app.js", "/api/v1/health", "/api/v1/auth/login", "/api/v1/auth/captcha"} {
		if !isPublicPath(path) {
			t.Fatalf("isPublicPath(%q) = false, want true", path)
		}
	}
}

func TestAuthPublicPathsProtectAPIs(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/api/v1/rules", "/api/v1/docker/mappings", "/api/v1/system/status", "/api/v1/users"} {
		if isPublicPath(path) {
			t.Fatalf("isPublicPath(%q) = true, want false", path)
		}
	}
}

func TestRootServesLoginPage(t *testing.T) {
	t.Parallel()

	path := "/"
	if !isPublicPath(path) {
		t.Fatalf("isPublicPath(%q) = false, want true", path)
	}
}
