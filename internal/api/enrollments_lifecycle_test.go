package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"iptables-web/internal/store"
)

func TestEnrollmentApprovalRejectsExpiredAndChangedApplications(t *testing.T) {
	for _, action := range []string{"expired before approval", "rejected during probe", "changed during probe", "expired during probe", "heartbeat during probe"} {
		t.Run(action, func(t *testing.T) {
			hosts := store.NewHostStore(filepath.Join(t.TempDir(), "hosts.json"), "controller-test-key-at-least-32-characters")
			if err := hosts.Load(); err != nil {
				t.Fatal(err)
			}
			h := NewEnrollmentHandler(hosts)
			var calls atomic.Int32
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				h.mu.Lock()
				switch action {
				case "rejected during probe":
					delete(h.pending, "00112233445566778899aabb")
					h.rejected["00112233445566778899aabb"] = time.Now().Add(time.Hour)
				case "changed during probe":
					h.pending["00112233445566778899aabb"].AgentKey = "ipwa_changed"
				case "expired during probe":
					h.pending["00112233445566778899aabb"].LastSeenAt = time.Now().Add(-pendingEnrollmentTTL - time.Second)
				case "heartbeat during probe":
					h.pending["00112233445566778899aabb"].LastNonce = "fresh"
					h.pending["00112233445566778899aabb"].LastSeenAt = time.Now()
				}
				h.mu.Unlock()
				w.Write([]byte(`{"success":true,"data":{}}`))
			}))
			defer agent.Close()
			pending := &pendingEnrollment{PendingEnrollmentResponse: PendingEnrollmentResponse{ID: "00112233445566778899aabb", Name: "node", BaseURL: agent.URL, SourceIP: "127.0.0.1", LastSeenAt: time.Now()}, PublicKey: "public", AgentKey: "ipwa_test"}
			if action == "expired before approval" {
				pending.LastSeenAt = time.Now().Add(-pendingEnrollmentTTL - time.Second)
			}
			h.pending["00112233445566778899aabb"] = pending
			// Exercise the HTTP selection path as well as the post-probe commit check.
			rec := httptest.NewRecorder()
			h.approve(rec, httptest.NewRequest(http.MethodPost, "/api/v1/agent-enrollments/approve", strings.NewReader(`{"ids":["00112233445566778899aabb"]}`)).WithContext(context.Background()))
			wantHosts := 0
			if action == "heartbeat during probe" {
				wantHosts = 1
			}
			if rec.Code != 200 || len(hosts.List()) != wantHosts {
				t.Fatalf("approval status=%d hosts=%d body=%s", rec.Code, len(hosts.List()), rec.Body.String())
			}
			if action == "expired before approval" && calls.Load() != 0 {
				t.Fatal("expired application was probed")
			}
			if action != "heartbeat during probe" && !strings.Contains(rec.Body.String(), `"success":false`) {
				t.Fatalf("invalid application approved: %s", rec.Body.String())
			}
		})
	}
}
