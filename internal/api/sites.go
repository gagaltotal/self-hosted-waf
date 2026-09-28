package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/lib/pq"

	"waf/internal/store"
)

func (s *Server) handleListSites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.db.ListSites(r.Context())
	if err != nil {
		s.log.Error("list sites failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list sites")
		return
	}
	writeJSON(w, http.StatusOK, sites)
}

func (s *Server) handleGetSite(w http.ResponseWriter, r *http.Request) {
	site, err := s.db.GetSite(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "site not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not fetch site")
		return
	}
	writeJSON(w, http.StatusOK, site)
}

type siteRequest struct {
	Name                string                `json:"name"`
	Domain              string                `json:"domain"`
	UpstreamURL         string                `json:"upstream_url"`
	Enabled             bool                  `json:"enabled"`
	Mode                string                `json:"mode"`
	BlockThreshold      int                   `json:"block_threshold"`
	RateLimitRPS        int                   `json:"rate_limit_rps"`
	RateLimitBurst      int                   `json:"rate_limit_burst"`
	BotChallengeEnabled bool                  `json:"bot_challenge_enabled"`
	BotChallengeMode    string                `json:"bot_challenge_mode"`
	TurnstileSiteKey    string                `json:"turnstile_site_key"`
	TurnstileSecretKey  string                `json:"turnstile_secret_key"`
	PoWDifficultyBits   int                   `json:"pow_difficulty_bits"`
	SensitivePaths      []store.SensitivePath `json:"sensitive_paths"`
	TrustedBotAllowlist []string              `json:"trusted_bot_allowlist"`
}

func (req *siteRequest) validate() error {
	if strings.TrimSpace(req.Name) == "" {
		return errors.New("name is required")
	}
	if strings.TrimSpace(req.Domain) == "" {
		return errors.New("domain is required")
	}
	u, err := url.Parse(req.UpstreamURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("upstream_url must be a valid absolute http:// or https:// URL")
	}
	if req.Mode != "block" && req.Mode != "monitor" {
		return errors.New(`mode must be "block" or "monitor"`)
	}
	if req.BotChallengeMode != "pow" && req.BotChallengeMode != "turnstile" {
		return errors.New(`bot_challenge_mode must be "pow" or "turnstile"`)
	}
	if req.RateLimitRPS <= 0 || req.RateLimitBurst <= 0 {
		return errors.New("rate_limit_rps and rate_limit_burst must be positive")
	}
	if req.BlockThreshold <= 0 {
		return errors.New("block_threshold must be positive")
	}
	if req.PoWDifficultyBits != 0 && (req.PoWDifficultyBits < 10 || req.PoWDifficultyBits > 22) {
		return errors.New("pow_difficulty_bits must be between 10 and 22")
	}
	for _, sp := range req.SensitivePaths {
		if sp.Prefix == "" || sp.RPS <= 0 || sp.Burst <= 0 {
			return errors.New("each sensitive path needs a non-empty prefix and positive rps/burst")
		}
	}
	return nil
}

func (req *siteRequest) toInput() store.SiteInput {
	return store.SiteInput{
		Name: strings.TrimSpace(req.Name), Domain: strings.ToLower(strings.TrimSpace(req.Domain)),
		UpstreamURL: req.UpstreamURL, Enabled: req.Enabled, Mode: req.Mode,
		BlockThreshold: req.BlockThreshold, RateLimitRPS: req.RateLimitRPS, RateLimitBurst: req.RateLimitBurst,
		BotChallengeEnabled: req.BotChallengeEnabled, BotChallengeMode: req.BotChallengeMode,
		TurnstileSiteKey: req.TurnstileSiteKey, TurnstileSecretKey: req.TurnstileSecretKey,
		PoWDifficultyBits: req.PoWDifficultyBits, SensitivePaths: req.SensitivePaths,
		TrustedBotAllowlist: req.TrustedBotAllowlist,
	}
}

func (s *Server) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	var req siteRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	site, err := s.db.CreateSite(r.Context(), req.toInput())
	if err != nil {
		if isUniqueViolation(err) {
			writeError(w, http.StatusConflict, "a site with this domain already exists")
			return
		}
		s.log.Error("create site failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create site")
		return
	}

	s.reloadRegistry(r.Context())
	s.log.Info("site created", "site_id", site.ID, "domain", site.Domain, "by_user", userIDFromContext(r))
	writeJSON(w, http.StatusCreated, site)
}

func (s *Server) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	existing, err := s.db.GetSite(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "site not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not fetch site")
		return
	}

	var req siteRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	input := req.toInput()
	// A blank secret in the request means "leave it unchanged" -- the API
	// never echoes the stored secret back (see store.Site's json:"-" tag),
	// so the dashboard cannot round-trip a value it was never given.
	if input.TurnstileSecretKey == "" {
		input.TurnstileSecretKey = existing.TurnstileSecretKey
	}

	site, err := s.db.UpdateSite(r.Context(), id, input)
	if err != nil {
		if isUniqueViolation(err) {
			writeError(w, http.StatusConflict, "a site with this domain already exists")
			return
		}
		s.log.Error("update site failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not update site")
		return
	}

	s.reloadRegistry(r.Context())
	s.log.Info("site updated", "site_id", site.ID, "domain", site.Domain, "by_user", userIDFromContext(r))
	writeJSON(w, http.StatusOK, site)
}

func (s *Server) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.db.DeleteSite(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "site not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not delete site")
		return
	}
	s.reloadRegistry(r.Context())
	s.log.Info("site deleted", "site_id", id, "by_user", userIDFromContext(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) reloadRegistry(ctx context.Context) {
	if err := s.registry.Reload(ctx); err != nil {
		s.log.Warn("registry reload after site change failed; will retry on next auto-refresh", "error", err)
	}
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}
