// Package challenge implements bot defense in front of protected sites.
// The default mechanism is a client-side proof-of-work (PoW) puzzle in the
// style of Anubis/Cloudflare's JS challenge: the visitor's browser must
// burn a small, tunable amount of CPU time before it is let through, which
// is cheap for a single real visitor but expensive at the scale an
// automated scraper or credential-stuffing bot needs to operate at. It
// requires no external service or API key, which matters for a self-hosted
// tool. An optional Cloudflare Turnstile integration (turnstile.go) is
// available for operators who want a "real" CAPTCHA instead.
package challenge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"waf/internal/security"
)

const (
	challengeTTL  = 5 * time.Minute  // how long a visitor has to solve the puzzle
	passTTL       = 45 * time.Minute // how long a solved pass is honoured before re-challenging
	minDifficulty = 10
	maxDifficulty = 22

	// DefaultDifficulty is benchmarked (see README) to average well under a
	// second on typical hardware using the pure-JS fallback hasher, while
	// still being a meaningful per-request cost at bot scale.
	DefaultDifficulty = 16
)

type PoW struct {
	secret []byte
	rdb    *redis.Client
}

func NewPoW(secret []byte, rdb *redis.Client) *PoW {
	return &PoW{secret: secret, rdb: rdb}
}

// IssueToken creates a stateless, tamper-evident challenge: a random nonce
// plus an issue time and difficulty, all authenticated with an HMAC so it
// can be verified later without any server-side storage or database lookup.
func (p *PoW) IssueToken(difficultyBits int) (token, nonce string, err error) {
	if difficultyBits < minDifficulty {
		difficultyBits = minDifficulty
	}
	if difficultyBits > maxDifficulty {
		difficultyBits = maxDifficulty
	}
	nonce, err = security.RandomToken(16)
	if err != nil {
		return "", "", err
	}
	payload := fmt.Sprintf("%s.%d.%d", nonce, time.Now().Unix(), difficultyBits)
	return security.SignedValue(p.secret, payload), nonce, nil
}

type parsedToken struct {
	nonce      string
	issuedAt   time.Time
	difficulty int
}

func (p *PoW) parseToken(token string) (*parsedToken, error) {
	payload, ok := security.ParseSignedValue(p.secret, token)
	if !ok {
		return nil, errors.New("invalid or tampered challenge token")
	}
	parts := strings.Split(payload, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed challenge token")
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, errors.New("malformed challenge timestamp")
	}
	diff, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, errors.New("malformed challenge difficulty")
	}
	issued := time.Unix(ts, 0)
	if time.Since(issued) > challengeTTL {
		return nil, errors.New("challenge expired, please retry")
	}
	if time.Since(issued) < -10*time.Second {
		return nil, errors.New("challenge issued in the future")
	}
	return &parsedToken{nonce: parts[0], issuedAt: issued, difficulty: diff}, nil
}

// VerifySolution checks that sha256(nonce + ":" + counter) has at least
// `difficulty` leading zero bits, as claimed by the token.
func (p *PoW) VerifySolution(token string, counter string) error {
	pt, err := p.parseToken(token)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(pt.nonce + ":" + counter))
	if leadingZeroBits(sum[:]) < pt.difficulty {
		return errors.New("proof-of-work does not meet required difficulty")
	}
	return nil
}

func leadingZeroBits(b []byte) int {
	count := 0
	for _, byteVal := range b {
		if byteVal == 0 {
			count += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if byteVal&(1<<uint(i)) == 0 {
				count++
			} else {
				return count
			}
		}
	}
	return count
}

// GrantPass records that a visitor has solved a challenge and returns an
// opaque cookie value good for passTTL. Subsequent requests bearing this
// cookie skip re-challenging (they are still fully subject to WAF
// inspection and rate limiting -- the bot-pass only ever bypasses the CPU
// puzzle, nothing else).
func (p *PoW) GrantPass(ctx context.Context, siteID string) (string, time.Duration, error) {
	tok, err := security.RandomToken(24)
	if err != nil {
		return "", 0, err
	}
	key := "botpass:" + siteID + ":" + hashShort(tok)
	if err := p.rdb.Set(ctx, key, "1", passTTL).Err(); err != nil {
		return "", 0, err
	}
	return tok, passTTL, nil
}

func (p *PoW) HasPass(ctx context.Context, siteID, cookieValue string) bool {
	if cookieValue == "" {
		return false
	}
	key := "botpass:" + siteID + ":" + hashShort(cookieValue)
	n, err := p.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false // Redis unreachable: fall through to (re-)challenge rather than error out
	}
	return n > 0
}

func hashShort(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
