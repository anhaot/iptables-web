package api

import (
	"context"
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

	for _, path := range []string{"/api/v1/rules", "/api/v1/auth/login", "/api/v1/auth/captcha", "/api/v1/auth/policy"} {
		if shouldSkipRateLimit(path) {
			t.Fatalf("shouldSkipRateLimit(%q) = true, want false", path)
		}
	}
}

func TestAuthPublicPathsAllowFrontendShell(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/", "/index.html", "/login.html", "/change-password.html", "/favicon.ico", "/favicon.svg", "/css/base.css", "/js/app.js", "/api/v1/health", "/api/v1/auth/login", "/api/v1/auth/captcha", "/api/v1/auth/policy"} {
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

func TestControllerMiddlewareProtectsUnauthorizedResponses(t *testing.T) {
	t.Setenv("AUTH_ENABLED", "true")
	h := NewHandler(store.NewJSONStore(filepath.Join(t.TempDir(), "rules.json")), nil)
	called := false
	handler := controllerMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}), h, nil, nil, nil, newAuthConfig(nil))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil))
	if recorder.Code != http.StatusUnauthorized || called {
		t.Fatalf("status=%d called=%v body=%s", recorder.Code, called, recorder.Body.String())
	}
	if recorder.Header().Get("X-Request-ID") == "" {
		t.Fatal("unauthorized response is missing X-Request-ID")
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" || recorder.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("unauthorized response is missing security headers: %#v", recorder.Header())
	}
}

func TestOnlyPostAgentEnrollmentRegisterIsPublic(t *testing.T) {
	t.Setenv("AUTH_ENABLED", "true")
	calls := 0
	handler := authMiddleware(newAuthConfig(nil))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))

	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollments/register", nil))
	if post.Code != http.StatusNoContent || calls != 1 {
		t.Fatalf("public register status=%d calls=%d", post.Code, calls)
	}

	for _, test := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/agent-enrollments/register"},
		{http.MethodGet, "/api/v1/agent-enrollments"},
		{http.MethodPost, "/api/v1/agent-enrollments/approve"},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, nil))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status=%d, want 401", test.method, test.path, recorder.Code)
		}
	}
	if calls != 1 {
		t.Fatalf("protected enrollment request reached handler; calls=%d", calls)
	}
}

func TestDynamicAPIKeyTakesEffectAndRevokesWithoutRestart(t *testing.T) {
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("API_KEY", "")
	keyStore := store.NewAPIKeyStore(filepath.Join(t.TempDir(), "api-keys.json"))
	if err := keyStore.Load(); err != nil {
		t.Fatal(err)
	}
	metadata, plaintext, err := keyStore.Create("controller")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	handler := authMiddleware(newAuthConfig(nil, keyStore))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))

	request := func() int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
		req.Header.Set("X-API-Key", plaintext)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Code
	}
	if status := request(); status != http.StatusNoContent {
		t.Fatalf("new dynamic key status = %d", status)
	}
	if err := keyStore.Delete(metadata.ID); err != nil {
		t.Fatal(err)
	}
	if status := request(); status != http.StatusUnauthorized {
		t.Fatalf("revoked dynamic key status = %d", status)
	}
	if calls != 1 {
		t.Fatalf("protected handler calls = %d, want 1", calls)
	}
}

func TestRootServesLoginPage(t *testing.T) {
	t.Parallel()

	path := "/"
	if !isPublicPath(path) {
		t.Fatalf("isPublicPath(%q) = false, want true", path)
	}
}

func TestLocalHostRequiredAllowsAssignedOrdinaryUser(t *testing.T) {
	calls := 0
	handler := localHostRequired()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))

	request := func(session *store.Session) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
		if session != nil {
			req = req.WithContext(context.WithValue(req.Context(), sessionKey, session))
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Code
	}
	if status := request(&store.Session{Role: "user"}); status != http.StatusForbidden {
		t.Fatalf("unassigned user status=%d", status)
	}
	if status := request(&store.Session{Role: "user", HostIDs: []string{"local"}}); status != http.StatusNoContent {
		t.Fatalf("assigned user status=%d", status)
	}
	if status := request(&store.Session{Role: "admin"}); status != http.StatusNoContent {
		t.Fatalf("admin status=%d", status)
	}
	if calls != 2 {
		t.Fatalf("protected handler calls=%d, want 2", calls)
	}
}
