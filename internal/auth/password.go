package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	pbkdf2Algo       = "$pbkdf2-sha256$"
	legacySHA256Algo = "$sha256$"
	pbkdf2Iterations = 210000
	saltSize         = 32
	keySize          = 32
)

// HashPassword hashes a password with PBKDF2-SHA256 and a random salt.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("生成盐值失败: %w", err)
	}
	hash := pbkdf2Key([]byte(password), salt, pbkdf2Iterations, keySize)
	return fmt.Sprintf("%s%d$%s$%s",
		pbkdf2Algo,
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword compares a password against a stored hash.
func VerifyPassword(password, encoded string) bool {
	if strings.HasPrefix(encoded, pbkdf2Algo) {
		return verifyPBKDF2(password, encoded)
	}
	return verifyLegacySHA256(password, encoded)
}

// NeedsRehash reports whether the stored password should be upgraded.
func NeedsRehash(encoded string) bool {
	if !strings.HasPrefix(encoded, pbkdf2Algo) {
		return true
	}
	rest := encoded[len(pbkdf2Algo):]
	parts := strings.Split(rest, "$")
	if len(parts) != 3 {
		return true
	}
	iterations, err := strconv.Atoi(parts[0])
	return err != nil || iterations < pbkdf2Iterations
}

func verifyPBKDF2(password, encoded string) bool {
	rest := encoded[len(pbkdf2Algo):]
	parts := strings.Split(rest, "$")
	if len(parts) != 3 {
		return false
	}
	iterations, err := strconv.Atoi(parts[0])
	if err != nil || iterations <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil || len(salt) != saltSize {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(expected) != keySize {
		return false
	}
	actual := pbkdf2Key([]byte(password), salt, iterations, len(expected))
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

func verifyLegacySHA256(password, encoded string) bool {
	if !strings.HasPrefix(encoded, legacySHA256Algo) {
		return false
	}
	rest := encoded[len(legacySHA256Algo):]
	parts := strings.SplitN(rest, "$", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	actual := hashWithSalt(password, salt)
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

func pbkdf2Key(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	key := make([]byte, 0, numBlocks*hashLen)
	var blockIndex [4]byte

	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(blockIndex[:], uint32(block))
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write(blockIndex[:])
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		key = append(key, t...)
	}
	return key[:keyLen]
}

func hashWithSalt(password string, salt []byte) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	return h.Sum(nil)
}
