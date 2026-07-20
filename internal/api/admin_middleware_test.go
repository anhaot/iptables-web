package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"iptables-web/internal/store"
)

func TestAdminRequiredRejectsNonAdminSession(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil)
	req = req.WithContext(context.WithValue(req.Context(), sessionKey, &store.Session{
		Username: "viewer",
		Role:     "user",
	}))
	rr := httptest.NewRecorder()

	adminRequired()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestAdminRequiredAllowsAdminSession(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil)
	req = req.WithContext(context.WithValue(req.Context(), sessionKey, &store.Session{
		Username: "admin",
		Role:     "admin",
	}))
	rr := httptest.NewRecorder()
	called := false

	adminRequired()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)

	if !called || rr.Code != http.StatusNoContent {
		t.Fatalf("called=%v status=%d, want called and %d", called, rr.Code, http.StatusNoContent)
	}
}

func TestAdminRequiredAllowsAPIKeyAndAuthDisabledModes(t *testing.T) {
	t.Parallel()

	for name, key := range map[string]contextKey{
		"api key":       apiKeyAuthKey,
		"auth disabled": authDisabledKey,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil)
			req = req.WithContext(context.WithValue(req.Context(), key, true))
			rr := httptest.NewRecorder()
			called := false

			adminRequired()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(rr, req)

			if !called || rr.Code != http.StatusNoContent {
				t.Fatalf("called=%v status=%d, want called and %d", called, rr.Code, http.StatusNoContent)
			}
		})
	}
}
