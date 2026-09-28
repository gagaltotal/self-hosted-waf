package store

import "time"

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// SensitivePath lets an operator apply a tighter rate limit to specific
// paths (e.g. /login, /wp-login.php) to blunt credential-stuffing /
// brute-force attempts without throttling the whole site.
type SensitivePath struct {
	Prefix string `json:"prefix"`
	RPS    int    `json:"rps"`
	Burst  int    `json:"burst"`
}

type Site struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	UpstreamURL string `json:"upstream_url"`
	Enabled     bool   `json:"enabled"`

	// Mode "block" actively rejects malicious requests; "monitor" only logs
	// them, useful when first rolling the WAF out in front of a new site to
	// tune rules before enforcing them.
	Mode           string `json:"mode"`
	BlockThreshold int    `json:"block_threshold"`

	RateLimitRPS   int `json:"rate_limit_rps"`
	RateLimitBurst int `json:"rate_limit_burst"`

	BotChallengeEnabled bool   `json:"bot_challenge_enabled"`
	BotChallengeMode    string `json:"bot_challenge_mode"` // "pow" | "turnstile"
	TurnstileSiteKey    string `json:"turnstile_site_key"`
	TurnstileSecretKey  string `json:"-"`
	PoWDifficultyBits   int    `json:"pow_difficulty_bits"`

	SensitivePaths      []SensitivePath `json:"sensitive_paths"`
	TrustedBotAllowlist []string        `json:"trusted_bot_allowlist"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AttackLog struct {
	ID         int64     `json:"id"`
	SiteID     string    `json:"site_id"`
	SiteName   string    `json:"site_name,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
	ClientIP   string    `json:"client_ip"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Category   string    `json:"category"`
	Action     string    `json:"action"`
	Score      int       `json:"score"`
	RuleIDs    []string  `json:"rule_ids"`
	UserAgent  string    `json:"user_agent"`
	Snippet    string    `json:"snippet"`
}

type StatsSummary struct {
	TotalRequests   int64            `json:"total_requests"`
	BlockedRequests int64            `json:"blocked_requests"`
	ChallengedCount int64            `json:"challenged_count"`
	RateLimited     int64            `json:"rate_limited_count"`
	ByCategory      map[string]int64 `json:"by_category"`
	Timeseries      []TimeseriesPt   `json:"timeseries"`
	TopIPs          []IPCount        `json:"top_ips"`
	TopSites        []SiteCount      `json:"top_sites"`
}

type TimeseriesPt struct {
	Bucket  time.Time `json:"bucket"`
	Blocked int64     `json:"blocked"`
	Total   int64     `json:"total"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

type SiteCount struct {
	SiteID   string `json:"site_id"`
	SiteName string `json:"site_name"`
	Count    int64  `json:"count"`
}
