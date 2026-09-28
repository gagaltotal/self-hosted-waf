package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

func scanSite(row interface {
	Scan(dest ...any) error
}) (*Site, error) {
	var s Site
	var sensitivePathsRaw, allowlistRaw []byte
	err := row.Scan(
		&s.ID, &s.Name, &s.Domain, &s.UpstreamURL, &s.Enabled,
		&s.Mode, &s.BlockThreshold,
		&s.RateLimitRPS, &s.RateLimitBurst,
		&s.BotChallengeEnabled, &s.BotChallengeMode,
		&s.TurnstileSiteKey, &s.TurnstileSecretKey, &s.PoWDifficultyBits,
		&sensitivePathsRaw, &allowlistRaw,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(sensitivePathsRaw, &s.SensitivePaths); err != nil {
		s.SensitivePaths = nil
	}
	if err := json.Unmarshal(allowlistRaw, &s.TrustedBotAllowlist); err != nil {
		s.TrustedBotAllowlist = nil
	}
	return &s, nil
}

const siteColumns = `
	id, name, domain, upstream_url, enabled,
	mode, block_threshold,
	rate_limit_rps, rate_limit_burst,
	bot_challenge_enabled, bot_challenge_mode,
	turnstile_site_key, turnstile_secret_key, pow_difficulty_bits,
	sensitive_paths, trusted_bot_allowlist,
	created_at, updated_at
`

func (db *DB) ListSites(ctx context.Context) ([]*Site, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+siteColumns+` FROM sites ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*Site{}
	for rows.Next() {
		s, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListEnabledSites is used by the proxy's in-memory registry refresh; it
// only needs to know about sites that are actually active.
func (db *DB) ListEnabledSites(ctx context.Context) ([]*Site, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+siteColumns+` FROM sites WHERE enabled = true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*Site{}
	for rows.Next() {
		s, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) GetSite(ctx context.Context, id string) (*Site, error) {
	row := db.QueryRowContext(ctx, `SELECT `+siteColumns+` FROM sites WHERE id = $1`, id)
	return scanSite(row)
}

type SiteInput struct {
	Name                string
	Domain              string
	UpstreamURL         string
	Enabled             bool
	Mode                string
	BlockThreshold      int
	RateLimitRPS        int
	RateLimitBurst      int
	BotChallengeEnabled bool
	BotChallengeMode    string
	TurnstileSiteKey    string
	TurnstileSecretKey  string
	PoWDifficultyBits   int
	SensitivePaths      []SensitivePath
	TrustedBotAllowlist []string
}

func (db *DB) CreateSite(ctx context.Context, in SiteInput) (*Site, error) {
	sp, err := json.Marshal(nonNilPaths(in.SensitivePaths))
	if err != nil {
		return nil, err
	}
	al, err := json.Marshal(nonNilStrings(in.TrustedBotAllowlist))
	if err != nil {
		return nil, err
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO sites (
			name, domain, upstream_url, enabled, mode, block_threshold,
			rate_limit_rps, rate_limit_burst,
			bot_challenge_enabled, bot_challenge_mode,
			turnstile_site_key, turnstile_secret_key, pow_difficulty_bits,
			sensitive_paths, trusted_bot_allowlist
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		RETURNING `+siteColumns, // #nosec: siteColumns is a fixed internal constant, not user input
		in.Name, in.Domain, in.UpstreamURL, in.Enabled, in.Mode, in.BlockThreshold,
		in.RateLimitRPS, in.RateLimitBurst,
		in.BotChallengeEnabled, in.BotChallengeMode,
		in.TurnstileSiteKey, in.TurnstileSecretKey, in.PoWDifficultyBits,
		sp, al,
	)
	return scanSite(row)
}

func (db *DB) UpdateSite(ctx context.Context, id string, in SiteInput) (*Site, error) {
	sp, err := json.Marshal(nonNilPaths(in.SensitivePaths))
	if err != nil {
		return nil, err
	}
	al, err := json.Marshal(nonNilStrings(in.TrustedBotAllowlist))
	if err != nil {
		return nil, err
	}

	row := db.QueryRowContext(ctx, `
		UPDATE sites SET
			name = $1, domain = $2, upstream_url = $3, enabled = $4,
			mode = $5, block_threshold = $6,
			rate_limit_rps = $7, rate_limit_burst = $8,
			bot_challenge_enabled = $9, bot_challenge_mode = $10,
			turnstile_site_key = $11, turnstile_secret_key = $12, pow_difficulty_bits = $13,
			sensitive_paths = $14, trusted_bot_allowlist = $15,
			updated_at = now()
		WHERE id = $16
		RETURNING `+siteColumns,
		in.Name, in.Domain, in.UpstreamURL, in.Enabled, in.Mode, in.BlockThreshold,
		in.RateLimitRPS, in.RateLimitBurst,
		in.BotChallengeEnabled, in.BotChallengeMode,
		in.TurnstileSiteKey, in.TurnstileSecretKey, in.PoWDifficultyBits,
		sp, al, id,
	)
	return scanSite(row)
}

func (db *DB) DeleteSite(ctx context.Context, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM sites WHERE id = $1`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func nonNilPaths(p []SensitivePath) []SensitivePath {
	if p == nil {
		return []SensitivePath{}
	}
	return p
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
