package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"iptables-web/internal/store"
)

func TestShouldSkipRateLimitForStaticAndHealth(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/", "/login.html", "/change-password.html", "/favicon.ico", "/css/base.css", "/js/app.js", "/api/v1/health"} {
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

	for _, path := range []string{"/", "/index.html", "/login.html", "/change-password.html", "/favicon.ico", "/favicon.svg", "/css/base.css", "/js/app.js", "/api/v1/health", "/api/v1/auth/login", "/api/v1/auth/captcha"} {
		if !isPublicPath(path) {
			t.Fatalf("isPublicPath(%q) = false, want true", path)
		}
	}
}

func TestAuthRequiresBootstrapPasswordChangeBeforeOtherAPIs(t *testing.T) {
	t.Setenv("AUTH_ENABLED", "true")
	users := store.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := users.Load(); err != nil {
		t.Fatal(err)
	}
	login, err := users.Login("admin", "admin123")
	if err != nil {
		t.Fatal(err)
	}
	cfg := newAuthConfig(users)
	called := false
	handler := authMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	blocked := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	blocked.Header.Set("Authorization", "Bearer "+login.Token)
	blockedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(blockedRecorder, blocked)
	if blockedRecorder.Code != http.StatusForbidden || !strings.Contains(blockedRecorder.Body.String(), "password_change_required") {
		t.Fatalf("blocked status=%d body=%s", blockedRecorder.Code, blockedRecorder.Body.String())
	}
	if called {
		t.Fatal("protected handler was called before bootstrap password change")
	}

	for _, path := range []string{"/api/v1/auth/session", "/api/v1/auth/password", "/api/v1/auth/logout"} {
		called = false
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer "+login.Token)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if !called || recorder.Code != http.StatusNoContent {
			t.Fatalf("%s called=%v status=%d", path, called, recorder.Code)
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
