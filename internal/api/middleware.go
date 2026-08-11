package api

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	appLog "iptables-web/internal/logging"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
)

type contextKey string

const requestIDKey contextKey = "request_id"
const sessionKey contextKey = "session"
const apiKeyAuthKey contextKey = "api_key_auth"
const authDisabledKey contextKey = "auth_disabled"
const requestLogIdentityKey contextKey = "request_log_identity"
const forwardedAuditIdentityKey contextKey = "forwarded_audit_identity"

type forwardedAuditIdentity struct {
	Actor    string
	Role     string
	RemoteIP string
}

type requestLogIdentity struct {
	actor string
}

func setRequestLogActor(r *http.Request, actor string) {
	if identity, ok := r.Context().Value(requestLogIdentityKey).(*requestLogIdentity); ok {
		identity.actor = actor
	}
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if !validRequestID(id) {
			id = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validRequestID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || strings.ContainsRune("-_.:", ch) {
			continue
		}
		return false
	}
	return true
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, status: 200}
		identity := &requestLogIdentity{actor: "anonymous"}
		r = r.WithContext(context.WithValue(r.Context(), requestLogIdentityKey, identity))
		next.ServeHTTP(wrapped, r)
		requestID, _ := r.Context().Value(requestIDKey).(string)
		actor := identity.actor
		appLog.Infof("request_id=%s actor=%s remote_ip=%s method=%s path=%s status=%d duration=%s",
			requestID, actor, remoteRequestIP(r.RemoteAddr), r.Method, r.URL.Path, wrapped.status, time.Since(start))
	})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				appLog.Errorf("PANIC: %v", rec)
				respondError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type authConfig struct {
	enabled     bool
	apiKey      string
	apiKeyStore *store.APIKeyStore
	userStore   *store.UserStore
}

func newAuthConfig(userStore *store.UserStore, apiKeyStores ...*store.APIKeyStore) *authConfig {
	authEnabled := true
	if os.Getenv("AUTH_ENABLED") == "false" {
		authEnabled = false
	}
	var apiKeyStore *store.APIKeyStore
	if len(apiKeyStores) > 0 {
		apiKeyStore = apiKeyStores[0]
	}
	return &authConfig{
		enabled:     authEnabled,
		apiKey:      os.Getenv("API_KEY"),
		apiKeyStore: apiKeyStore,
		userStore:   userStore,
	}
}

func authMiddleware(cfg *authConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Public endpoints — no auth required
			if isPublicPath(r.URL.Path) || (r.Method == http.MethodPost && r.URL.Path == "/api/v1/agent-enrollments/register") {
				next.ServeHTTP(w, r)
				return
			}

			// Always try to attach session from token if user store is available
			if cfg.userStore != nil {
				token := extractBearerToken(r)
				if token != "" {
					if sess, err := cfg.userStore.ValidateSession(token); err == nil {
						ctx := context.WithValue(r.Context(), sessionKey, sess)
						r = r.WithContext(ctx)
						setRequestLogActor(r, sess.Username+"/"+sess.Role)
					}
				}
			}

			// Auth disabled — allow all (but session was attached if valid)
			if !cfg.enabled {
				setRequestLogActor(r, "auth-disabled/admin")
				ctx := context.WithValue(r.Context(), authDisabledKey, true)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Auth enabled — require either valid session or API key

			// 1. Check session (already attached above)
			if sess, ok := r.Context().Value(sessionKey).(*store.Session); ok {
				if sess.MustChangePassword && !isPasswordChangeAllowedPath(r.URL.Path) {
					respondError(w, http.StatusForbidden, "password_change_required", "首次登录或密码到期，必须先修改密码")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// 2. Check API Key (backward compatible)
			key := r.Header.Get("X-API-Key")
			legacyKeyOK := cfg.apiKey != "" && subtle.ConstantTimeCompare([]byte(key), []byte(cfg.apiKey)) == 1
			dynamicKeyOK := cfg.apiKeyStore != nil && cfg.apiKeyStore.Validate(key)
			if key != "" && (legacyKeyOK || dynamicKeyOK) {
				setRequestLogActor(r, "api-key/admin")
				ctx := context.WithValue(r.Context(), apiKeyAuthKey, true)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			respondError(w, http.StatusUnauthorized, "unauthorized", "请先登录或提供有效的 API Key")
		})
	}
}

// isPublicPath returns true for endpoints that don't require authentication.
func isPublicPath(path string) bool {
	public := []string{
		"/api/v1/health",
		"/api/v1/auth/login",
		"/api/v1/auth/captcha",
		"/api/v1/auth/policy",
		"/",
		"/index.html",
		"/login.html",
		"/change-password.html",
		"/favicon.ico",
		"/favicon.svg",
	}
	for _, p := range public {
		if path == p {
			return true
		}
	}
	// Serve static assets (css/js) without auth so login page can render
	if strings.HasPrefix(path, "/css/") || strings.HasPrefix(path, "/js/") {
		return true
	}
	return false
}

func isPasswordChangeAllowedPath(path string) bool {
	return path == "/api/v1/auth/session" ||
		path == "/api/v1/auth/password" ||
		path == "/api/v1/auth/logout"
}

// adminRequired is middleware that checks the session has admin role.
func adminRequired() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := r.Context().Value(sessionKey).(*store.Session)
			apiKeyOK, _ := r.Context().Value(apiKeyAuthKey).(bool)
			authDisabled, _ := r.Context().Value(authDisabledKey).(bool)
			if authDisabled || apiKeyOK {
				next.ServeHTTP(w, r)
				return
			}
			if !ok || sess.Role != "admin" {
				respondError(w, http.StatusForbidden, "forbidden", "需要管理员权限")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// localHostRequired protects controller-local firewall APIs. Administrators,
// API keys and auth-disabled deployments retain access; ordinary users must be
// explicitly assigned the stable local host ID.
func localHostRequired() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if disabled, _ := r.Context().Value(authDisabledKey).(bool); disabled {
				next.ServeHTTP(w, r)
				return
			}
			if apiKeyOK, _ := r.Context().Value(apiKeyAuthKey).(bool); apiKeyOK {
				next.ServeHTTP(w, r)
				return
			}
			sess, ok := r.Context().Value(sessionKey).(*store.Session)
			if !ok {
				respondError(w, http.StatusForbidden, "forbidden", "没有本机防火墙权限")
				return
			}
			if sess.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}
			for _, hostID := range sess.HostIDs {
				if hostID == model.LocalHostID {
					next.ServeHTTP(w, r)
					return
				}
			}
			respondError(w, http.StatusForbidden, "forbidden", "没有本机防火墙权限")
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Basic in-memory rate limiter
type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	limit    int
	window   time.Duration
}

type visitor struct {
	count       int
	windowStart time.Time
	lastSeen    time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		visitors: make(map[string]*visitor),
		limit:    limit,
		window:   window,
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, exists := rl.visitors[ip]
	if !exists || now.Sub(v.windowStart) >= rl.window {
		if !exists && len(rl.visitors) >= 10000 {
			for key, entry := range rl.visitors {
				if now.Sub(entry.lastSeen) >= rl.window {
					delete(rl.visitors, key)
				}
			}
			if len(rl.visitors) >= 10000 {
				return false
			}
		}
		rl.visitors[ip] = &visitor{count: 1, windowStart: now, lastSeen: now}
		return true
	}

	v.lastSeen = now
	v.count++
	return v.count <= rl.limit
}

func rateLimitMiddleware(limit int, window time.Duration) func(http.Handler) http.Handler {
	rl := newRateLimiter(limit, window)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if shouldSkipRateLimit(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			ip := strings.TrimSpace(r.RemoteAddr)
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}
			if !rl.allow(ip) {
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", window.Seconds()))
				respondError(w, http.StatusTooManyRequests, "rate_limited", "too many requests, please slow down")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func shouldSkipRateLimit(path string) bool {
	if path == "/" || path == "/login.html" || path == "/change-password.html" || path == "/favicon.ico" {
		return true
	}
	if strings.HasPrefix(path, "/css/") || strings.HasPrefix(path, "/js/") {
		return true
	}
	if path == "/api/v1/health" {
		return true
	}
	return false
}
