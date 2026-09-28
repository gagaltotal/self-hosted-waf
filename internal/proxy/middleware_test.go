package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"waf/internal/store"
)

func TestEffectiveRateLimitUsesSensitivePathWhenMatched(t *testing.T) {
	site := &store.Site{
		ID: "site1", RateLimitRPS: 20, RateLimitBurst: 40,
		SensitivePaths: []store.SensitivePath{
			{Prefix: "/login", RPS: 2, Burst: 5},
			{Prefix: "/api/", RPS: 10, Burst: 15},
		},
	}

	rps, burst, scope := effectiveRateLimit(site, "/login")
	if rps != 2 || burst != 5 {
		t.Fatalf("expected sensitive path limits (2,5), got (%d,%d)", rps, burst)
	}
	if scope != "site:site1:path:/login" {
		t.Fatalf("unexpected scope: %s", scope)
	}
}

func TestEffectiveRateLimitFallsBackToSiteDefault(t *testing.T) {
	site := &store.Site{ID: "site1", RateLimitRPS: 20, RateLimitBurst: 40}
	rps, burst, scope := effectiveRateLimit(site, "/some/random/page")
	if rps != 20 || burst != 40 {
		t.Fatalf("expected site defaults (20,40), got (%d,%d)", rps, burst)
	}
	if scope != "site:site1" {
		t.Fatalf("unexpected scope: %s", scope)
	}
}

func TestWantsHTMLChallenge(t *testing.T) {
	cases := []struct {
		method, accept string
		want           bool
	}{
		{http.MethodGet, "text/html,application/xhtml+xml", true},
		{http.MethodGet, "", true},                  // missing Accept is itself a signal, default to challenging
		{http.MethodGet, "application/json", false}, // explicit API client
		{http.MethodGet, "*/*", true},               // curl-like default; deliberately still gated
		{http.MethodPost, "text/html", false},       // never gate non-GET/HEAD (forms, webhooks, APIs)
		{http.MethodHead, "text/html", true},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "/", nil)
		if c.accept != "" {
			r.Header.Set("Accept", c.accept)
		}
		got := wantsHTMLChallenge(r)
		if got != c.want {
			t.Errorf("wantsHTMLChallenge(method=%s, accept=%q) = %v, want %v", c.method, c.accept, got, c.want)
		}
	}
}

func TestIsAllowlistedByUserAgent(t *testing.T) {
	site := &store.Site{TrustedBotAllowlist: []string{"Googlebot", "203.0.113.0/24"}}
	if !isAllowlisted(site, "198.51.100.9", "Mozilla/5.0 (compatible; Googlebot/2.1)") {
		t.Error("expected Googlebot UA to be allowlisted")
	}
	if isAllowlisted(site, "198.51.100.9", "curl/8.0") {
		t.Error("did not expect curl UA to be allowlisted")
	}
}

func TestIsAllowlistedByCIDR(t *testing.T) {
	site := &store.Site{TrustedBotAllowlist: []string{"203.0.113.0/24"}}
	if !isAllowlisted(site, "203.0.113.42", "AnyAgent/1.0") {
		t.Error("expected IP inside allowlisted CIDR to be allowlisted")
	}
	if isAllowlisted(site, "198.51.100.1", "AnyAgent/1.0") {
		t.Error("did not expect IP outside allowlisted CIDR to be allowlisted")
	}
}

func TestBotPassCookieValue(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if v := botPassCookieValue(r); v != "" {
		t.Fatalf("expected empty value with no cookie, got %q", v)
	}
	r.AddCookie(&http.Cookie{Name: botPassCookieName, Value: "abc123"})
	if v := botPassCookieValue(r); v != "abc123" {
		t.Fatalf("expected abc123, got %q", v)
	}
}

func TestUnmatchedHostReturns404(t *testing.T) {
	// The registry with no sites loaded must deny by default rather than
	// falling through to any handler.
	reg := NewRegistry(nil, nil)
	if _, ok := reg.Match("unknown.example.com"); ok {
		t.Fatal("expected no match for a domain with no configured site")
	}
}
