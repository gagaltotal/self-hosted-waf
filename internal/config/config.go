// Package config loads and validates all runtime configuration from
// environment variables. Nothing is hardcoded, and the process refuses to
// start if a security-critical value is missing or looks unsafe (e.g. a
// secret that is empty or too short). Failing fast at startup is much safer
// than silently running with a weak or default secret.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	// Network
	ProxyHTTPAddr  string // public reverse-proxy listener (plain HTTP)
	ProxyHTTPSAddr string // public reverse-proxy listener (TLS), empty = disabled
	AdminAddr      string // admin API + dashboard listener

	TLSCertFile string
	TLSKeyFile  string

	// Trusted proxies: CIDRs allowed to set X-Forwarded-For / X-Real-IP.
	// If empty, the WAF NEVER trusts forwarded headers and always uses the
	// raw TCP peer address. This prevents IP-spoofing bypass of rate
	// limiting and IP blocklists.
	TrustedProxies []string

	// Storage
	DatabaseURL string
	RedisAddr   string
	RedisUser   string
	RedisPass   string
	RedisDB     int

	// Secrets
	SecretKey []byte // 32+ random bytes, used for HMAC (CSRF tokens, PoW challenge nonces)

	// Bootstrap admin account (optional; if unset a random password is
	// generated on first run and printed once to the logs).
	AdminEmail    string
	AdminPassword string

	// Behaviour
	LogLevel           string
	FailOpenOnInfraErr bool // if Redis is unreachable, allow traffic through rather than block everything

	// Session / cookie
	CookieSecure bool // set false only for local HTTP development
}

func Load() (*Config, error) {
	c := &Config{
		ProxyHTTPAddr:  getEnv("PROXY_HTTP_ADDR", ":8080"),
		ProxyHTTPSAddr: getEnv("PROXY_HTTPS_ADDR", ""),
		AdminAddr:      getEnv("ADMIN_ADDR", ":9000"),
		TLSCertFile:    getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:     getEnv("TLS_KEY_FILE", ""),
		DatabaseURL:    getEnv("DATABASE_URL", ""),
		RedisAddr:      getEnv("REDIS_ADDR", "redis:6379"),
		RedisUser:      getEnv("REDIS_USER", ""),
		RedisPass:      getEnv("REDIS_PASSWORD", ""),
		AdminEmail:     getEnv("ADMIN_EMAIL", ""),
		AdminPassword:  getEnv("ADMIN_PASSWORD", ""),
		LogLevel:       getEnv("LOG_LEVEL", "info"),
	}

	redisDB, err := strconv.Atoi(getEnv("REDIS_DB", "0"))
	if err != nil {
		return nil, fmt.Errorf("REDIS_DB must be an integer: %w", err)
	}
	c.RedisDB = redisDB

	if tp := getEnv("TRUSTED_PROXIES", ""); tp != "" {
		for _, p := range strings.Split(tp, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				c.TrustedProxies = append(c.TrustedProxies, p)
			}
		}
	}

	c.FailOpenOnInfraErr = getEnv("FAIL_OPEN_ON_INFRA_ERROR", "false") == "true"
	c.CookieSecure = getEnv("COOKIE_SECURE", "true") == "true"

	secretHex := getEnv("WAF_SECRET_KEY", "")
	if len(secretHex) < 32 {
		return nil, fmt.Errorf("WAF_SECRET_KEY is missing or too short (need at least 32 characters); generate one with: openssl rand -hex 32")
	}
	c.SecretKey = []byte(secretHex)

	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if c.RedisAddr == "" {
		return nil, fmt.Errorf("REDIS_ADDR is required")
	}
	if c.RedisPass == "" {
		return nil, fmt.Errorf("REDIS_PASSWORD is required (refusing to run Redis without auth)")
	}

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return nil, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must both be set, or both left empty")
	}
	if c.ProxyHTTPSAddr != "" && c.TLSCertFile == "" {
		return nil, fmt.Errorf("PROXY_HTTPS_ADDR is set but no TLS_CERT_FILE/TLS_KEY_FILE provided")
	}

	return c, nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
