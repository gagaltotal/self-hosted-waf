// Package security provides password hashing and random token utilities
// used by the admin authentication system.
//
// Password hashing deliberately uses only the Go standard library
// (crypto/hmac, crypto/sha256) instead of pulling in an external module.
// PBKDF2-HMAC-SHA256 is a NIST-approved (SP 800-132), fully specified KDF
// (RFC 8018) -- implementing it here is just composing the standard
// library's audited HMAC/SHA-256 primitives according to that spec, not
// inventing new cryptography. This keeps the dependency graph (and
// therefore the supply-chain attack surface of a security product) as
// small as possible. The iteration count follows OWASP's current
// recommendation for PBKDF2-HMAC-SHA256.
package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const (
	pbkdf2Iterations = 600_000 // OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
	pbkdf2KeyLen     = 32
	saltLen          = 16
	hashScheme       = "pbkdf2-sha256"
)

// pbkdf2 implements RFC 8018 PBKDF2 using HMAC-SHA256 as the PRF.
func pbkdf2(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	numBlocks := (keyLen + hLen - 1) / hLen

	dk := make([]byte, 0, numBlocks*hLen)
	buf := make([]byte, 4)

	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(buf, uint32(block))

		prf.Reset()
		prf.Write(salt)
		prf.Write(buf)
		u := prf.Sum(nil)

		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// HashPassword returns a self-describing hash string:
// pbkdf2-sha256$<iterations>$<base64 salt>$<base64 hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	hash := pbkdf2([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLen)

	return fmt.Sprintf("%s$%d$%s$%s",
		hashScheme,
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword checks a plaintext password against a stored hash string
// produced by HashPassword. Comparison is constant-time.
func VerifyPassword(password, stored string) (bool, error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return false, fmt.Errorf("unrecognized password hash format")
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false, fmt.Errorf("invalid iteration count in stored hash")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("invalid salt encoding")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("invalid hash encoding")
	}

	got := pbkdf2([]byte(password), salt, iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
