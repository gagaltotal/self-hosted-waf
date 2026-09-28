package proxy

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"waf/internal/store"
)

// Registry holds the current set of enabled protected sites in memory,
// keyed by domain, so matching an incoming request's Host header never
// needs a database round trip on the hot path. It is refreshed both
// on-demand (the admin API calls Reload immediately after any site change)
// and periodically as a safety net.
type Registry struct {
	mu       sync.RWMutex
	byDomain map[string]*store.Site

	db  *store.DB
	log *slog.Logger
}

func NewRegistry(db *store.DB, log *slog.Logger) *Registry {
	return &Registry{
		byDomain: map[string]*store.Site{},
		db:       db,
		log:      log,
	}
}

func (r *Registry) Reload(ctx context.Context) error {
	sites, err := r.db.ListEnabledSites(ctx)
	if err != nil {
		return err
	}
	m := make(map[string]*store.Site, len(sites))
	for _, s := range sites {
		m[strings.ToLower(s.Domain)] = s
	}
	r.mu.Lock()
	r.byDomain = m
	r.mu.Unlock()
	return nil
}

func (r *Registry) Match(host string) (*store.Site, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byDomain[host]
	return s, ok
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byDomain)
}

// StartAutoRefresh periodically reloads the registry in the background so
// changes made through any means (including a future second admin replica)
// are eventually picked up even if an explicit Reload call was missed.
func (r *Registry) StartAutoRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := r.Reload(ctx); err != nil {
					r.log.Warn("registry auto-refresh failed", "error", err)
				}
			}
		}
	}()
}
