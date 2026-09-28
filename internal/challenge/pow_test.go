package challenge

import (
	"crypto/sha256"
	"strconv"
	"testing"
	"time"

	"waf/internal/security"
)

func testSecret() []byte { return []byte("test-secret-at-least-32-bytes-long!!") }

// solve mimics exactly what the browser's pure-JS SHA-256 loop does
// (verified byte-for-byte identical to Node's crypto.createHash in the
// implementation notes), just using Go's stdlib SHA-256 instead -- both
// compute the same standard hash function over the same "nonce:counter"
// string, so this exercises the real issue/verify contract end to end.
func solve(nonce string, difficulty int) string {
	counter := 0
	for {
		sum := sha256.Sum256([]byte(nonce + ":" + strconv.Itoa(counter)))
		if leadingZeroBits(sum[:]) >= difficulty {
			return strconv.Itoa(counter)
		}
		counter++
	}
}

func TestPoWIssueSolveVerifyRoundTrip(t *testing.T) {
	p := NewPoW(testSecret(), nil)
	token, nonce, err := p.IssueToken(12) // small difficulty so the test runs fast
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	counter := solve(nonce, 12)
	if err := p.VerifySolution(token, counter); err != nil {
		t.Fatalf("expected valid solution to verify, got: %v", err)
	}
}

func TestPoWRejectsWrongCounter(t *testing.T) {
	p := NewPoW(testSecret(), nil)
	token, _, err := p.IssueToken(20) // high difficulty: "0" almost certainly won't satisfy it
	if err != nil {
		t.Fatal(err)
	}
	if err := p.VerifySolution(token, "0"); err == nil {
		t.Fatal("expected an unsolved/incorrect counter to fail verification")
	}
}

func TestPoWRejectsTamperedToken(t *testing.T) {
	p := NewPoW(testSecret(), nil)
	token, nonce, err := p.IssueToken(10)
	if err != nil {
		t.Fatal(err)
	}
	counter := solve(nonce, 10)

	tampered := token + "x"
	if err := p.VerifySolution(tampered, counter); err == nil {
		t.Fatal("expected tampered token to fail HMAC verification")
	}
}

func TestPoWRejectsExpiredToken(t *testing.T) {
	p := NewPoW(testSecret(), nil)
	// Build an already-expired token manually by issuing then waiting is too
	// slow for a unit test, so we construct the payload the same way
	// IssueToken does but with a stale timestamp, signed with the same
	// (package-internal) secret and helper it uses internally.
	nonce, err := security.RandomToken(16)
	if err != nil {
		t.Fatal(err)
	}
	stalePayload := nonce + "." + strconv.FormatInt(time.Now().Add(-1*time.Hour).Unix(), 10) + ".10"
	staleToken := security.SignedValue(p.secret, stalePayload)

	counter := solve(nonce, 10)
	if err := p.VerifySolution(staleToken, counter); err == nil {
		t.Fatal("expected an expired challenge token to be rejected")
	}
}

func TestPoWDifficultyIsClamped(t *testing.T) {
	p := NewPoW(testSecret(), nil)
	token, _, err := p.IssueToken(999) // way above maxDifficulty
	if err != nil {
		t.Fatal(err)
	}
	pt, err := p.parseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if pt.difficulty != maxDifficulty {
		t.Fatalf("expected difficulty clamped to %d, got %d", maxDifficulty, pt.difficulty)
	}
}

func TestLeadingZeroBits(t *testing.T) {
	cases := []struct {
		b    []byte
		want int
	}{
		{[]byte{0x00, 0x00, 0xFF}, 16},
		{[]byte{0xFF}, 0},
		{[]byte{0x0F}, 4},
		{[]byte{0x00, 0x01}, 15},
		{[]byte{0x00, 0x00, 0x00}, 24},
	}
	for _, c := range cases {
		got := leadingZeroBits(c.b)
		if got != c.want {
			t.Errorf("leadingZeroBits(%v) = %d, want %d", c.b, got, c.want)
		}
	}
}
