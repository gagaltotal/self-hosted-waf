package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// RandomToken returns a URL-safe, base64-encoded random token with n bytes
// of entropy from crypto/rand (never math/rand).
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns a SHA-256 hex digest of a token, used so that only the
// hash of session/API tokens is ever stored server-side (in Redis) --
// compromise of the datastore alone does not yield usable session tokens.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SignHMAC produces a base64url-encoded HMAC-SHA256 signature over payload
// using key.
func SignHMAC(key []byte, payload string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyHMAC checks a signature in constant time.
func VerifyHMAC(key []byte, payload, signature string) bool {
	expected := SignHMAC(key, payload)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) == 1
}

// SignedValue builds a "value.signature" token authenticated with key. It is
// used for small, stateless, tamper-evident values (CSRF tokens, PoW
// challenge nonces) that do not need a database round trip to validate.
func SignedValue(key []byte, value string) string {
	return value + "." + SignHMAC(key, value)
}

// ParseSignedValue validates a token built by SignedValue and returns the
// original value.
func ParseSignedValue(key []byte, token string) (string, bool) {
	idx := strings.LastIndex(token, ".")
	if idx < 0 {
		return "", false
	}
	value, sig := token[:idx], token[idx+1:]
	if !VerifyHMAC(key, value, sig) {
		return "", false
	}
	return value, true
}

// FormatUint is a tiny helper kept here to avoid importing strconv all over
// the codebase for this one common need.
func FormatUint(v uint64) string {
	return strconv.FormatUint(v, 10)
}
