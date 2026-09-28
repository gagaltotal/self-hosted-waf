package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"waf/internal/challenge"
	"waf/internal/detection"
	"waf/internal/httpx"
	"waf/internal/ratelimit"
	"waf/internal/store"
)

// challengeVerifyPath is a reserved path handled by the WAF itself on every
// protected domain. It is never forwarded upstream, so a protected
// application does not need to (and should not) implement anything at this
// path itself.
const challengeVerifyPath = "/.waf-internal/challenge/verify"

const botPassCookieName = "_waf_bp"

type ctxKey int

const (
	ctxSite ctxKey = iota
	ctxClientIP
)

type Handler struct {
	registry       *Registry
	engine         *detection.Engine
	limiter        *ratelimit.Limiter
	pow            *challenge.PoW
	trustedProxies *httpx.TrustedProxies
	logs           *logQueue
	log            *slog.Logger
	reverseProxy   *httputil.ReverseProxy
}

type Deps struct {
	Registry       *Registry
	Engine         *detection.Engine
	Limiter        *ratelimit.Limiter
	PoW            *challenge.PoW
	TrustedProxies *httpx.TrustedProxies
	DB             *store.DB
	Log            *slog.Logger
}

func NewHandler(d Deps) *Handler {
	h := &Handler{
		registry:       d.Registry,
		engine:         d.Engine,
		limiter:        d.Limiter,
		pow:            d.PoW,
		trustedProxies: d.TrustedProxies,
		logs:           newLogQueue(d.DB, d.Log),
		log:            d.Log,
	}

	h.reverseProxy = &httputil.ReverseProxy{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
		},
		Rewrite: func(pr *httputil.ProxyRequest) {
			site, _ := pr.In.Context().Value(ctxSite).(*store.Site)
			clientIP, _ := pr.In.Context().Value(ctxClientIP).(string)

			if site != nil {
				if target, err := url.Parse(site.UpstreamURL); err == nil {
					pr.SetURL(target)
				}
			}
			// Preserve the original public-facing Host so the upstream app
			// sees the domain the visitor actually used (matches common
			// reverse-proxy convention, e.g. nginx's proxy_set_header Host $host).
			pr.Out.Host = pr.In.Host

			// Never trust-and-forward whatever the client claimed: always
			// overwrite with our own authoritative determination of the
			// client IP so the upstream application cannot be fed a
			// spoofed X-Forwarded-For.
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
			pr.Out.Header.Set("X-Real-IP", clientIP)
			proto := "http"
			if pr.In.TLS != nil {
				proto = "https"
			}
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			d.Log.Warn("upstream proxy error", "error", err, "host", r.Host, "path", r.URL.Path)
			writeText(w, http.StatusBadGateway, "Bad Gateway")
		},
	}

	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := h.trustedProxies.ClientIP(r)
	ctx := context.WithValue(r.Context(), ctxClientIP, clientIP)
	r = r.WithContext(ctx)

	// Cheapest possible check first: an IP already in the penalty box for
	// repeated violations never even reaches rule matching.
	if h.limiter.IsQuarantined(r.Context(), clientIP) {
		writeText(w, http.StatusForbidden, "Forbidden")
		return
	}

	site, ok := h.registry.Match(r.Host)
	if !ok {
		// Deny by default: an unrecognized Host header never falls through
		// to some accidental default backend.
		writeText(w, http.StatusNotFound, "Not Found")
		return
	}

	ctx = context.WithValue(r.Context(), ctxSite, site)
	r = r.WithContext(ctx)

	if r.URL.Path == challengeVerifyPath {
		h.handleChallengeVerify(w, r, site, clientIP)
		return
	}

	rps, burst, scope := effectiveRateLimit(site, r.URL.Path)
	if d := h.limiter.Allow(r.Context(), scope, clientIP, rps, burst); !d.Allowed {
		h.limiter.Strike(r.Context(), clientIP)
		h.logs.Enqueue(store.AttackLog{
			SiteID: site.ID, ClientIP: clientIP, Method: r.Method, Path: r.URL.Path,
			Category: "rate_limit", Action: "blocked", Score: 0,
			UserAgent: r.Header.Get("User-Agent"),
		})
		w.Header().Set("Retry-After", "1")
		writeText(w, http.StatusTooManyRequests, "Too Many Requests")
		return
	}

	if site.BotChallengeEnabled && wantsHTMLChallenge(r) && !isAllowlisted(site, clientIP, r.Header.Get("User-Agent")) {
		if !h.pow.HasPass(r.Context(), site.ID, botPassCookieValue(r)) {
			h.serveChallenge(w, r, site)
			return
		}
	}

	bodyBuf, err := detection.BufferBody(r)
	if err != nil {
		h.log.Warn("failed to buffer request body for inspection", "error", err)
		writeText(w, http.StatusBadRequest, "Bad Request")
		return
	}

	verdict := h.engine.Inspect(r, bodyBuf, site.BlockThreshold)
	if verdict.Score > 0 {
		// Default to blocking on any confirmed verdict. Only an explicit
		// "monitor" mode (deliberately chosen while tuning a new site)
		// downgrades this to logging-only -- an empty or unexpected Mode
		// value fails safe (blocks) rather than fail-open.
		action := "monitored"
		if verdict.Block && site.Mode != "monitor" {
			action = "blocked"
		}
		h.logs.Enqueue(store.AttackLog{
			SiteID: site.ID, ClientIP: clientIP, Method: r.Method, Path: r.URL.Path,
			Category: string(verdict.TopCategory()), Action: action, Score: verdict.Score,
			RuleIDs: verdict.RuleIDs(), UserAgent: r.Header.Get("User-Agent"),
			Snippet: verdict.FirstSnippet(),
		})
		if action == "blocked" {
			h.limiter.Strike(r.Context(), clientIP)
			writeText(w, http.StatusForbidden, "Forbidden")
			return
		}
	}

	h.reverseProxy.ServeHTTP(w, r)
}

func effectiveRateLimit(site *store.Site, path string) (rps, burst int, scope string) {
	for _, sp := range site.SensitivePaths {
		if sp.Prefix != "" && strings.HasPrefix(path, sp.Prefix) {
			return sp.RPS, sp.Burst, "site:" + site.ID + ":path:" + sp.Prefix
		}
	}
	return site.RateLimitRPS, site.RateLimitBurst, "site:" + site.ID
}

// wantsHTMLChallenge decides whether this request is a browser page
// navigation (which can execute the JS puzzle) as opposed to an API call,
// asset fetch, or webhook (which cannot). The bot challenge only ever
// intercepts the former; non-GET/HEAD requests and requests that clearly
// expect JSON/XML/etc are left to rate limiting and WAF inspection instead
// -- see the README for why this scope boundary is deliberate.
func wantsHTMLChallenge(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return true
	}
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

func isAllowlisted(site *store.Site, ip, userAgent string) bool {
	ua := strings.ToLower(userAgent)
	for _, raw := range site.TrustedBotAllowlist {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(entry); err == nil {
			if parsed := net.ParseIP(ip); parsed != nil && ipnet.Contains(parsed) {
				return true
			}
			continue
		}
		if parsed := net.ParseIP(entry); parsed != nil {
			if parsed.String() == ip {
				return true
			}
			continue
		}
		if ua != "" && strings.Contains(ua, strings.ToLower(entry)) {
			return true
		}
	}
	return false
}

func botPassCookieValue(r *http.Request) string {
	c, err := r.Cookie(botPassCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func (h *Handler) serveChallenge(w http.ResponseWriter, r *http.Request, site *store.Site) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	if site.BotChallengeMode == "turnstile" && site.TurnstileSiteKey != "" {
		token, _, err := h.pow.IssueToken(site.PoWDifficultyBits) // reused only to carry a signed, expiring token
		if err != nil {
			writeText(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if err := challenge.RenderTurnstilePage(w, site.TurnstileSiteKey, token, challengeVerifyPath); err != nil {
			h.log.Warn("failed to render turnstile page", "error", err)
		}
		return
	}

	difficulty := site.PoWDifficultyBits
	if difficulty <= 0 {
		difficulty = challenge.DefaultDifficulty
	}
	token, nonce, err := h.pow.IssueToken(difficulty)
	if err != nil {
		writeText(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := challenge.RenderPoWPage(w, nonce, token, difficulty, challengeVerifyPath); err != nil {
		h.log.Warn("failed to render pow page", "error", err)
	}
}

type verifyRequest struct {
	Token             string `json:"token"`
	Counter           string `json:"counter"`
	TurnstileResponse string `json:"turnstileResponse"`
}

func (h *Handler) handleChallengeVerify(w http.ResponseWriter, r *http.Request, site *store.Site, clientIP string) {
	if r.Method != http.MethodPost {
		writeText(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid body"})
		return
	}
	var req verifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json"})
		return
	}

	var verified bool
	if site.BotChallengeMode == "turnstile" && site.TurnstileSiteKey != "" {
		ok, err := challenge.VerifyTurnstile(r.Context(), site.TurnstileSecretKey, req.TurnstileResponse, clientIP)
		if err != nil {
			h.log.Warn("turnstile verification error", "error", err)
		}
		verified = ok
	} else {
		if len(req.Counter) > 32 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid counter"})
			return
		}
		verified = h.pow.VerifySolution(req.Token, req.Counter) == nil
	}

	if !verified {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "challenge not satisfied"})
		return
	}

	passValue, ttl, err := h.pow.GrantPass(r.Context(), site.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "internal error"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     botPassCookieName,
		Value:    passValue,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeText(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
