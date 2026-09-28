package store

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

func (db *DB) InsertAttackLog(ctx context.Context, l AttackLog) error {
	ruleIDs := l.RuleIDs
	if ruleIDs == nil {
		ruleIDs = []string{}
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO attack_logs (
			site_id, client_ip, method, path, category, action, score, rule_ids, user_agent, snippet
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, l.SiteID, l.ClientIP, l.Method, truncate(l.Path, 2048), l.Category, l.Action, l.Score,
		pq.Array(ruleIDs), truncate(l.UserAgent, 512), truncate(l.Snippet, 1024))
	return err
}

type LogFilter struct {
	SiteID   string
	Category string
	Action   string
	ClientIP string
	Since    *time.Time
	Until    *time.Time
	Limit    int
	Offset   int
}

func (db *DB) ListAttackLogs(ctx context.Context, f LogFilter) ([]*AttackLog, int64, error) {
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}

	if f.SiteID != "" {
		where = append(where, "al.site_id = "+arg(f.SiteID))
	}
	if f.Category != "" {
		where = append(where, "al.category = "+arg(f.Category))
	}
	if f.Action != "" {
		where = append(where, "al.action = "+arg(f.Action))
	}
	if f.ClientIP != "" {
		where = append(where, "al.client_ip = "+arg(f.ClientIP))
	}
	if f.Since != nil {
		where = append(where, "al.occurred_at >= "+arg(*f.Since))
	}
	if f.Until != nil {
		where = append(where, "al.occurred_at <= "+arg(*f.Until))
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}

	var total int64
	countQuery := `SELECT count(*) FROM attack_logs al ` + whereSQL
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	limitArg := arg(limit)
	offsetArg := arg(f.Offset)

	query := `
		SELECT al.id, al.site_id, coalesce(s.name, ''), al.occurred_at, host(al.client_ip),
		       al.method, al.path, al.category, al.action, al.score, al.rule_ids, al.user_agent, al.snippet
		FROM attack_logs al
		LEFT JOIN sites s ON s.id = al.site_id
		` + whereSQL + `
		ORDER BY al.occurred_at DESC
		LIMIT ` + limitArg + ` OFFSET ` + offsetArg

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*AttackLog
	for rows.Next() {
		var l AttackLog
		if err := rows.Scan(&l.ID, &l.SiteID, &l.SiteName, &l.OccurredAt, &l.ClientIP,
			&l.Method, &l.Path, &l.Category, &l.Action, &l.Score, pq.Array(&l.RuleIDs),
			&l.UserAgent, &l.Snippet); err != nil {
			return nil, 0, err
		}
		out = append(out, &l)
	}
	if out == nil {
		out = []*AttackLog{}
	}
	return out, total, rows.Err()
}

// GetStatsSummary aggregates counts for the dashboard overview page over the
// given lookback window. Every collection field is initialized to an empty
// (non-nil) slice/map so the JSON response always contains [] / {} rather
// than null when there is no data yet -- a fresh install with zero attack
// logs must render an empty dashboard cleanly, not crash the frontend.
func (db *DB) GetStatsSummary(ctx context.Context, since time.Time) (*StatsSummary, error) {
	s := &StatsSummary{
		ByCategory: map[string]int64{},
		Timeseries: []TimeseriesPt{},
		TopIPs:     []IPCount{},
		TopSites:   []SiteCount{},
	}

	err := db.QueryRowContext(ctx, `
		SELECT
			count(*),
			count(*) FILTER (WHERE action = 'blocked'),
			count(*) FILTER (WHERE action = 'challenged'),
			count(*) FILTER (WHERE category = 'rate_limit')
		FROM attack_logs WHERE occurred_at >= $1
	`, since).Scan(&s.TotalRequests, &s.BlockedRequests, &s.ChallengedCount, &s.RateLimited)
	if err != nil {
		return nil, err
	}

	catRows, err := db.QueryContext(ctx, `
		SELECT category, count(*) FROM attack_logs
		WHERE occurred_at >= $1 GROUP BY category ORDER BY count(*) DESC
	`, since)
	if err != nil {
		return nil, err
	}
	for catRows.Next() {
		var cat string
		var n int64
		if err := catRows.Scan(&cat, &n); err != nil {
			catRows.Close()
			return nil, err
		}
		s.ByCategory[cat] = n
	}
	catRows.Close()

	tsRows, err := db.QueryContext(ctx, `
		SELECT date_trunc('hour', occurred_at) AS bucket,
		       count(*) FILTER (WHERE action = 'blocked') AS blocked,
		       count(*) AS total
		FROM attack_logs
		WHERE occurred_at >= $1
		GROUP BY bucket ORDER BY bucket ASC
	`, since)
	if err != nil {
		return nil, err
	}
	for tsRows.Next() {
		var pt TimeseriesPt
		if err := tsRows.Scan(&pt.Bucket, &pt.Blocked, &pt.Total); err != nil {
			tsRows.Close()
			return nil, err
		}
		s.Timeseries = append(s.Timeseries, pt)
	}
	tsRows.Close()

	ipRows, err := db.QueryContext(ctx, `
		SELECT host(client_ip), count(*) c FROM attack_logs
		WHERE occurred_at >= $1 AND action != 'monitored'
		GROUP BY client_ip ORDER BY c DESC LIMIT 10
	`, since)
	if err != nil {
		return nil, err
	}
	for ipRows.Next() {
		var ipc IPCount
		if err := ipRows.Scan(&ipc.IP, &ipc.Count); err != nil {
			ipRows.Close()
			return nil, err
		}
		s.TopIPs = append(s.TopIPs, ipc)
	}
	ipRows.Close()

	siteRows, err := db.QueryContext(ctx, `
		SELECT al.site_id, coalesce(s.name, 'unknown'), count(*) c
		FROM attack_logs al LEFT JOIN sites s ON s.id = al.site_id
		WHERE al.occurred_at >= $1
		GROUP BY al.site_id, s.name ORDER BY c DESC LIMIT 10
	`, since)
	if err != nil {
		return nil, err
	}
	for siteRows.Next() {
		var sc SiteCount
		if err := siteRows.Scan(&sc.SiteID, &sc.SiteName, &sc.Count); err != nil {
			siteRows.Close()
			return nil, err
		}
		s.TopSites = append(s.TopSites, sc)
	}
	siteRows.Close()

	return s, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
