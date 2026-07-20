package auth

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestHashPasswordUsesPBKDF2(t *testing.T) {
	hash, err := HashPassword("secret123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(hash, pbkdf2Algo) {
		t.Fatalf("HashPassword() prefix = %q, want %q", hash, pbkdf2Algo)
	}
	if !VerifyPassword("secret123", hash) {
		t.Fatal("VerifyPassword() rejected a valid PBKDF2 hash")
	}
	if VerifyPassword("wrong", hash) {
		t.Fatal("VerifyPassword() accepted an invalid password")
	}
	if NeedsRehash(hash) {
		t.Fatal("NeedsRehash() reported fresh hash as stale")
	}
}

func TestVerifyPasswordSupportsLegacySHA256(t *testing.T) {
	salt := []byte("12345678901234567890123456789012")
	hash := hashWithSalt("secret123", salt)
	encoded := legacySHA256Algo + hex.EncodeToString(salt) + "$" + hex.EncodeToString(hash)

	if !VerifyPassword("secret123", encoded) {
		t.Fatal("VerifyPassword() rejected a valid legacy hash")
	}
	if !NeedsRehash(encoded) {
		t.Fatal("NeedsRehash() did not flag legacy hash")
	}
}
