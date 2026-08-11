package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSignedRequestVerifiesAndDetectsTampering(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	req, err := NewSignedRequest(privateKey, "node-a", "prod", "http://192.0.2.10:33802", "ipwa_secret", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := req.Verify(now, time.Minute); err != nil {
		t.Fatalf("valid signed request rejected: %v", err)
	}
	req.BaseURL = "http://127.0.0.1:33802"
	if _, err := req.Verify(now, time.Minute); err == nil {
		t.Fatal("tampered enrollment request passed signature verification")
	}
}

func TestSignedRequestRejectsStaleTimestamp(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	req, err := NewSignedRequest(privateKey, "node-a", "", "http://192.0.2.10:33802", "ipwa_secret", time.Now().Add(-10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := req.Verify(time.Now(), 5*time.Minute); err == nil {
		t.Fatal("stale enrollment request was accepted")
	}
}
