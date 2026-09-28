// Package detection implements the WAF's rule-matching engine: SQL
// injection, XSS, command injection, and path traversal detection over
// HTTP requests.
//
// A deliberate design choice: all matching uses Go's regexp package, which
// is backed by RE2. RE2 guarantees linear-time matching with no
// catastrophic backtracking, unlike PCRE-family engines. That means a
// hostile payload crafted specifically to make a naive regex WAF hang
// (a ReDoS attack on the WAF itself) cannot do so here -- this is a
// structural property of the engine, not something that depends on how
// carefully each pattern below is written.
package detection

import (
	"net/url"
	"strings"
)

const (
	maxDecodePasses = 3
	maxFieldLen     = 8192
)

// Normalize repeatedly percent-decodes a string (to catch double/triple
// URL-encoding evasion such as %252e%252e%252f), strips NUL bytes, and
// returns a lowercase copy for case-insensitive matching.
//
// Decoding uses url.QueryUnescape uniformly (which also maps '+' to a
// space) even for values taken from the path. That is not strictly
// "correct" per the URL spec for path segments, but a WAF's normalization
// should err toward seeing more of what an attacker could mean, not toward
// perfectly reconstructing intended semantics -- over-decoding only makes
// evasion via +-as-space harder, never easier.
func Normalize(raw string) string {
	s := raw
	if len(s) > maxFieldLen {
		s = s[:maxFieldLen]
	}
	for i := 0; i < maxDecodePasses; i++ {
		next, err := url.QueryUnescape(s)
		if err != nil || next == s {
			break
		}
		s = next
	}
	s = strings.ReplaceAll(s, "\x00", "")
	return strings.ToLower(s)
}
