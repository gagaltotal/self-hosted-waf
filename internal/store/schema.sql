-- WAF schema. Applied automatically on startup (idempotent: IF NOT EXISTS
-- everywhere) so a fresh Postgres volume bootstraps itself.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sites (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                   TEXT NOT NULL,
    domain                 TEXT NOT NULL UNIQUE,
    upstream_url           TEXT NOT NULL,
    enabled                BOOLEAN NOT NULL DEFAULT true,
    mode                   TEXT NOT NULL DEFAULT 'block',   -- 'block' | 'monitor'
    block_threshold        INTEGER NOT NULL DEFAULT 7,
    rate_limit_rps         INTEGER NOT NULL DEFAULT 10,
    rate_limit_burst       INTEGER NOT NULL DEFAULT 20,
    bot_challenge_enabled  BOOLEAN NOT NULL DEFAULT true,
    bot_challenge_mode     TEXT NOT NULL DEFAULT 'pow',      -- 'pow' | 'turnstile'
    turnstile_site_key     TEXT NOT NULL DEFAULT '',
    turnstile_secret_key   TEXT NOT NULL DEFAULT '',
    pow_difficulty_bits    INTEGER NOT NULL DEFAULT 16,
    sensitive_paths        JSONB NOT NULL DEFAULT '[]',      -- [{"prefix":"/login","rps":2,"burst":5}]
    trusted_bot_allowlist  JSONB NOT NULL DEFAULT '[]',      -- ["Googlebot","203.0.113.0/24"]
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attack_logs (
    id           BIGSERIAL PRIMARY KEY,
    site_id      UUID REFERENCES sites(id) ON DELETE CASCADE,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    client_ip    INET NOT NULL,
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    category     TEXT NOT NULL,               -- sqli|xss|cmdi|path_traversal|rate_limit|bot|other
    action       TEXT NOT NULL,                -- blocked|challenged|monitored
    score        INTEGER NOT NULL DEFAULT 0,
    rule_ids     TEXT[] NOT NULL DEFAULT '{}',
    user_agent   TEXT NOT NULL DEFAULT '',
    snippet      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_attack_logs_site_time ON attack_logs (site_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_logs_time       ON attack_logs (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_logs_category   ON attack_logs (category);
CREATE INDEX IF NOT EXISTS idx_attack_logs_ip          ON attack_logs (client_ip);
