package security

import (
	"encoding/hex"
	"testing"
)

// Vectors independently cross-checked against Node.js's native
// crypto.pbkdf2Sync(pw, salt, iter, 32, "sha256") to make sure this
// hand-written implementation is byte-for-byte correct.
func TestPBKDF2Vectors(t *testing.T) {
	cases := []struct {
		pw, salt   string
		iterations int
		want       string
	}{
		{"password", "salt", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
		{"correct horse battery staple", "somesalt123456", 600000, "ff8fe55f26e3a87b6ccfcf1393a4075a4e84cd8487f8b51eca19f07fa4510f8e"},
	}
	for _, c := range cases {
		got := pbkdf2([]byte(c.pw), []byte(c.salt), c.iterations, 32)
		gotHex := hex.EncodeToString(got)
		if gotHex != c.want {
			t.Errorf("pbkdf2(%q,%q,%d) = %s, want %s", c.pw, c.salt, c.iterations, gotHex, c.want)
		}
	}
}

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("SuperSecret!123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword("SuperSecret!123", hash)
	if err != nil || !ok {
		t.Fatalf("expected correct password to verify, got ok=%v err=%v", ok, err)
	}

	ok, err = VerifyPassword("wrong-password", hash)
	if err != nil || ok {
		t.Fatalf("expected wrong password to fail verification, got ok=%v err=%v", ok, err)
	}
}

func TestHashPasswordProducesUniqueSalts(t *testing.T) {
	h1, _ := HashPassword("same-password")
	h2, _ := HashPassword("same-password")
	if h1 == h2 {
		t.Fatal("two hashes of the same password must differ (random salt)")
	}
}
