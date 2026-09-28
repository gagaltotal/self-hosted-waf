// Package cache wraps the Redis client used for all fast, ephemeral state:
// rate-limit counters, temporary IP quarantine, and bot-challenge session
// markers. None of this data needs to survive forever, which is exactly
// what Redis with TTLs is good at, and keeps Postgres focused on durable
// records (sites, users, attack history).
package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Cache struct {
	rdb *redis.Client
}

func Open(ctx context.Context, addr, username, password string, db int) (*Cache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		Username:     username,
		Password:     password,
		DB:           db,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		return nil, fmt.Errorf("connecting to redis: %w", err)
	}
	return &Cache{rdb: rdb}, nil
}

func (c *Cache) Client() *redis.Client { return c.rdb }

func (c *Cache) Close() error { return c.rdb.Close() }

// Healthy reports whether Redis is currently reachable. Used by the proxy
// middleware to decide fail-open vs fail-closed behaviour if Redis goes
// down, and by the /healthz endpoint.
func (c *Cache) Healthy(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	return c.rdb.Ping(ctx).Err() == nil
}
