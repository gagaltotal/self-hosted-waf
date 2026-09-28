// Package ratelimit implements per-IP token-bucket rate limiting and a
// progressive quarantine ("penalty box") for IPs that repeatedly trip
// limits or WAF rules. State lives in Redis so limits are enforced
// correctly even if the WAF is later scaled to multiple replicas.
package ratelimit

import (
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// tokenBucketScript is evaluated atomically by Redis so concurrent requests
// against the same bucket can never race each other into over-admitting
// traffic. It refills `rate` tokens/sec up to `capacity`, and consumes one
// token per allowed request.
const tokenBucketScript = `
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local bucket = redis.call("HMGET", key, "tokens", "ts")
local tokens = tonumber(bucket[1])
local ts = tonumber(bucket[2])

if tokens == nil then
  tokens = capacity
  ts = now
end

local delta = math.max(0, now - ts)
local refill = delta * rate / 1000.0
tokens = math.min(capacity, tokens + refill)

local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end

redis.call("HMSET", key, "tokens", tostring(tokens), "ts", tostring(now))
local ttl = math.ceil((capacity / rate) * 1000) + 2000
redis.call("PEXPIRE", key, ttl)

return {allowed, tokens}
`

const (
	strikeWindow    = 10 * time.Minute
	strikeThreshold = 25
	quarantineTTL   = 15 * time.Minute
)

type Limiter struct {
	rdb      *redis.Client
	script   *redis.Script
	failOpen bool
	log      *slog.Logger
}

func New(rdb *redis.Client, failOpen bool, log *slog.Logger) *Limiter {
	return &Limiter{
		rdb:      rdb,
		script:   redis.NewScript(tokenBucketScript),
		failOpen: failOpen,
		log:      log,
	}
}

type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
}

// Allow consumes one token from the bucket identified by scope+ip. rps/burst
// come from the site's configuration (or hardcoded defaults for
// system-level limiters like the admin login endpoint).
func (l *Limiter) Allow(ctx context.Context, scope, ip string, rps, burst int) Decision {
	if rps <= 0 {
		rps = 1
	}
	if burst <= 0 {
		burst = rps
	}

	key := "rl:" + scope + ":" + ip
	now := time.Now().UnixMilli()

	res, err := l.script.Run(ctx, l.rdb, []string{key}, rps, burst, now).Result()
	if err != nil {
		l.log.Warn("rate limiter: redis error, degrading", "error", err, "fail_open", l.failOpen)
		// Infra failure: the operator chooses whether availability
		// (fail-open) or strict enforcement (fail-closed) matters more.
		// Fail-open is the default because a Redis outage should not be
		// able to take every protected site offline.
		return Decision{Allowed: l.failOpen}
	}

	arr, ok := res.([]interface{})
	if !ok || len(arr) < 1 {
		return Decision{Allowed: l.failOpen}
	}
	allowed, _ := arr[0].(int64)
	if allowed == 1 {
		return Decision{Allowed: true}
	}
	retryAfter := time.Second
	if rps > 0 {
		retryAfter = time.Second / time.Duration(rps)
		if retryAfter < 100*time.Millisecond {
			retryAfter = 100 * time.Millisecond
		}
	}
	return Decision{Allowed: false, RetryAfter: retryAfter}
}

// Strike records a violation (rate-limit trip or WAF block) against an IP.
// After enough strikes in a short window, the IP is quarantined -- refused
// outright, cheaply, before any expensive rule evaluation runs on
// subsequent requests.
func (l *Limiter) Strike(ctx context.Context, ip string) {
	key := "strikes:" + ip
	n, err := l.rdb.Incr(ctx, key).Result()
	if err != nil {
		l.log.Warn("rate limiter: strike incr failed", "error", err)
		return
	}
	if n == 1 {
		l.rdb.Expire(ctx, key, strikeWindow)
	}
	if n >= strikeThreshold {
		l.Quarantine(ctx, ip, quarantineTTL)
	}
}

func (l *Limiter) Quarantine(ctx context.Context, ip string, d time.Duration) {
	if err := l.rdb.Set(ctx, "quarantine:"+ip, "1", d).Err(); err != nil {
		l.log.Warn("rate limiter: quarantine set failed", "error", err)
	}
}

func (l *Limiter) IsQuarantined(ctx context.Context, ip string) bool {
	n, err := l.rdb.Exists(ctx, "quarantine:"+ip).Result()
	if err != nil {
		// If Redis is down we cannot know: fail open on this specific
		// check regardless of global setting, since a false positive here
		// (refusing everyone) is worse than a temporarily-unenforced
		// quarantine list.
		return false
	}
	return n > 0
}
