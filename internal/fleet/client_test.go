package fleet

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"iptables-web/internal/model"
)

func TestDoWithResponseLimitRejectsOversizedResponse(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	remote := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 65)))
	}))
	remote.Listener = listener
	remote.Start()
	defer remote.Close()

	client := NewClient(0)
	host := &model.ManagedHost{BaseURL: remote.URL, Enabled: true}
	_, err = client.DoWithResponseLimit(context.Background(), host, "key", http.MethodGet, "/", "", nil, "", 64)
	if err == nil || !strings.Contains(err.Error(), "exceeds 64 byte limit") {
		t.Fatalf("oversized response error = %v", err)
	}
}
