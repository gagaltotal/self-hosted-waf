package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"waf/internal/store"
)

func validSiteRequest() siteRequest {
	return siteRequest{
		Name: "My Site", Domain: "example.com", UpstreamURL: "http://backend:3000",
		Enabled: true, Mode: "block", BlockThreshold: 7,
		RateLimitRPS: 10, RateLimitBurst: 20,
		BotChallengeEnabled: true, BotChallengeMode: "pow", PoWDifficultyBits: 16,
	}
}

func TestSiteRequestValidateAcceptsGoodInput(t *testing.T) {
	req := validSiteRequest()
	if err := req.validate(); err != nil {
		t.Fatalf("expected valid request to pass, got: %v", err)
	}
}

func TestSiteRequestValidateRejectsMissingName(t *testing.T) {
	req := validSiteRequest()
	req.Name = "  "
	if err := req.validate(); err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestSiteRequestValidateRejectsBadUpstreamURL(t *testing.T) {
	cases := []string{"", "not-a-url", "ftp://example.com", "javascript:alert(1)", "example.com"}
	for _, u := range cases {
		req := validSiteRequest()
		req.UpstreamURL = u
		if err := req.validate(); err == nil {
			t.Errorf("expected error for upstream_url=%q", u)
		}
	}
}

func TestSiteRequestValidateRejectsBadMode(t *testing.T) {
	req := validSiteRequest()
	req.Mode = "allow-everything"
	if err := req.validate(); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestSiteRequestValidateRejectsNonPositiveRateLimits(t *testing.T) {
	req := validSiteRequest()
	req.RateLimitRPS = 0
	if err := req.validate(); err == nil {
		t.Fatal("expected error for zero rate_limit_rps")
	}
}

func TestSiteRequestValidateRejectsBadSensitivePath(t *testing.T) {
	req := validSiteRequest()
	req.SensitivePaths = []store.SensitivePath{{Prefix: "/login", RPS: 0, Burst: 5}}
	if err := req.validate(); err == nil {
		t.Fatal("expected error for sensitive path with zero rps")
	}
}

func TestSiteRequestValidateRejectsOutOfRangeDifficulty(t *testing.T) {
	req := validSiteRequest()
	req.PoWDifficultyBits = 30
	if err := req.validate(); err == nil {
		t.Fatal("expected error for pow_difficulty_bits out of range")
	}
}

func TestCSRFSafeMethodsAlwaysPass(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		r := httptest.NewRequest(m, "/api/sites", nil)
		if !validCSRF(r) {
			t.Errorf("expected safe method %s to bypass CSRF check", m)
		}
	}
}

func TestCSRFRejectsMissingToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/sites", nil)
	if validCSRF(r) {
		t.Fatal("expected POST with no CSRF cookie/header to fail")
	}
}

func TestCSRFRejectsMismatchedToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/sites", nil)
	r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "aaa"})
	r.Header.Set(csrfHeaderName, "bbb")
	if validCSRF(r) {
		t.Fatal("expected mismatched CSRF cookie/header to fail")
	}
}

func TestCSRFAcceptsMatchingToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/sites", nil)
	r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "matching-token"})
	r.Header.Set(csrfHeaderName, "matching-token")
	if !validCSRF(r) {
		t.Fatal("expected matching CSRF cookie/header to pass")
	}
}

func TestIsUniqueViolationFalseForGenericError(t *testing.T) {
	if isUniqueViolation(errNotAPqError{}) {
		t.Fatal("expected a non-pq error to not be classified as a unique violation")
	}
}

type errNotAPqError struct{}

func (errNotAPqError) Error() string { return "some other db error" }
