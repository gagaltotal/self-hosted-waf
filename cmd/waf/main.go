// Command waf is the entrypoint for the self-hosted WAF. It runs two
// independent HTTP listeners in one process:
//
//   - the public reverse proxy (PROXY_HTTP_ADDR / PROXY_HTTPS_ADDR), which
//     receives all traffic bound for protected sites, and
//   - the admin API + dashboard (ADMIN_ADDR), used to manage sites and
//     review attack logs.
//
// Keeping these on separate ports means the admin surface is never exposed
// on the same listener that receives arbitrary traffic from the internet;
// see the README for the recommended network setup (bind ADMIN_ADDR to
// localhost or an internal network only).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"waf/internal/api"
	"waf/internal/cache"
	"waf/internal/challenge"
	"waf/internal/config"
	"waf/internal/detection"
	"waf/internal/httpx"
	"waf/internal/logging"
	"waf/internal/proxy"
	"waf/internal/ratelimit"
	"waf/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		// Logging isn't set up yet if config failed, so this goes straight
		// to stderr -- but it's exactly the kind of message (a missing
		// secret, a missing DSN) an operator needs to see immediately.
		os.Stderr.WriteString("fatal: " + err.Error() + "\n")
		os.Exit(1)
	}

	log := logging.New(cfg.LogLevel)
	log.Info("starting waf")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := connectDBWithRetry(ctx, cfg.DatabaseURL, log)
	if err != nil {
		log.Error("could not connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	rdb, err := connectRedisWithRetry(ctx, cfg, log)
	if err != nil {
		log.Error("could not connect to redis", "error", err)
		os.Exit(1)
	}
	defer rdb.Close()

	if err := api.Bootstrap(ctx, db, log, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Error("admin bootstrap failed", "error", err)
		os.Exit(1)
	}

	registry := proxy.NewRegistry(db, log)
	if err := registry.Reload(ctx); err != nil {
		log.Error("initial site registry load failed", "error", err)
		os.Exit(1)
	}
	log.Info("loaded protected sites", "count", registry.Count())
	registry.StartAutoRefresh(ctx, 30*time.Second)

	trustedProxies := httpx.NewTrustedProxies(cfg.TrustedProxies)
	limiter := ratelimit.New(rdb.Client(), cfg.FailOpenOnInfraErr, log)
	pow := challenge.NewPoW(cfg.SecretKey, rdb.Client())
	engine := detection.NewEngine(detection.DefaultRules)

	proxyHandler := proxy.NewHandler(proxy.Deps{
		Registry:       registry,
		Engine:         engine,
		Limiter:        limiter,
		PoW:            pow,
		TrustedProxies: trustedProxies,
		DB:             db,
		Log:            log,
	})

	proxySrv, err := proxy.NewServer(cfg.ProxyHTTPAddr, cfg.ProxyHTTPSAddr, cfg.TLSCertFile, cfg.TLSKeyFile, proxyHandler, log)
	if err != nil {
		log.Error("could not start proxy server", "error", err)
		os.Exit(1)
	}

	adminAPI, err := api.NewServer(api.Deps{
		DB:             db,
		Redis:          rdb.Client(),
		Limiter:        limiter,
		Registry:       registry,
		TrustedProxies: trustedProxies,
		CookieSecure:   cfg.CookieSecure,
		Log:            log,
	})
	if err != nil {
		log.Error("could not start admin api", "error", err)
		os.Exit(1)
	}

	adminSrv := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           adminAPI.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errc := make(chan error, 3)
	proxySrv.Start(errc)
	go func() {
		log.Info("admin api listening", "addr", cfg.AdminAddr)
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errc:
		log.Error("fatal listener error, shutting down", "error", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := proxySrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("proxy server shutdown error", "error", err)
	}
	if err := adminSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("admin server shutdown error", "error", err)
	}
	log.Info("shutdown complete")
}

func connectDBWithRetry(ctx context.Context, dsn string, log *slog.Logger) (*store.DB, error) {
	const maxAttempts = 30
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		db, err := store.Open(ctx, dsn)
		if err == nil {
			return db, nil
		}
		lastErr = err
		log.Warn("database not ready yet, retrying", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, lastErr
}

func connectRedisWithRetry(ctx context.Context, cfg *config.Config, log *slog.Logger) (*cache.Cache, error) {
	const maxAttempts = 30
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c, err := cache.Open(ctx, cfg.RedisAddr, cfg.RedisUser, cfg.RedisPass, cfg.RedisDB)
		if err == nil {
			return c, nil
		}
		lastErr = err
		log.Warn("redis not ready yet, retrying", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, lastErr
}
