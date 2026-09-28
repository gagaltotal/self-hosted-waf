# Self-Hosted Web Application Firewall

A self-hosted WAF that sits in front of your website as a reverse proxy: it
inspects every HTTP request for SQL injection, XSS, command injection, and
path traversal; rate-limits and challenges abusive clients; and gives you a
dashboard to manage protected sites and review what it caught. The backend
is Go, the dashboard is React, and the whole thing runs as three containers
under Docker Compose.

**Read [SECURITY.md](SECURITY.md) before deploying.** It explains exactly
what this system does and does not protect against -- that context matters
more than any feature list.

## Quick start

Requirements: Docker and Docker Compose. Nothing else needs to be installed
on the host.

```bash
git clone <this project> waf && cd waf
cp .env.example .env
```

Edit `.env` and fill in:

```bash
# generate a real secret:
openssl rand -hex 32
# paste it as WAF_SECRET_KEY=... in .env, and set real
# POSTGRES_PASSWORD / REDIS_PASSWORD values too
```

Then:

```bash
docker compose up -d --build
docker compose logs -f waf
```

Watch the startup logs for a line like this (only appears once, on the very
first run, if you didn't set `ADMIN_EMAIL`/`ADMIN_PASSWORD` in `.env`):

```
=== INITIAL ADMIN ACCOUNT CREATED === email=admin@localhost password=<random>
```

Log in at `http://localhost:9000` with that email/password and **change the
password immediately** (there's a "change password" option once the admin
API is extended with a settings page, or call
`POST /api/auth/change-password` directly -- see [API](#admin-api)).

Then add your first site from the **Sites** page: give it a name, the
public domain visitors will use, and the upstream URL of your actual
application server. Point your DNS (or your local `/etc/hosts` for testing)
at the machine running this WAF, and traffic to that domain now flows
through inspection before reaching your app.

## Architecture

```
                         ┌─────────────────────────────────────┐
                         │              waf (Go)                │
  Internet ──── :80/:443 │→ quarantine → rate limit → bot check │──▶ your app
  (visitors)             │→ WAF inspection (SQLi/XSS/CmdI/...)  │   (upstream)
                         │                                       │
  You (admin) ── :9000   │→ session auth → REST API + dashboard │──▶ Postgres
                         └─────────────────────────────────────┘──▶ Redis
```

One Go binary runs two independent HTTP listeners:

- **Proxy listener** (`PROXY_HTTP_ADDR` / `PROXY_HTTPS_ADDR`, published on
  ports 80/443): receives all public traffic to protected sites and runs it
  through the detection pipeline before forwarding to your upstream.
- **Admin listener** (`ADMIN_ADDR`, published on `127.0.0.1:9000` only by
  default): serves the REST API and the dashboard.

They're kept on separate ports deliberately: the surface that receives
arbitrary internet traffic and the surface that manages your sites should
never be the same listener. See "Securing the admin panel" below before
you expose port 9000 beyond your local machine.

**Postgres** stores durable records: sites, admin users, attack logs.
**Redis** stores fast, ephemeral state: rate-limit counters, IP quarantine,
bot-challenge sessions, and admin sessions -- all with TTLs, nothing that
needs to survive forever.

### Request pipeline (proxy listener)

1. **Quarantine check** -- an IP with 25+ violations in 10 minutes is
   refused immediately, before any regex runs.
2. **Site matching** -- the `Host` header is matched against configured
   sites. No match means a `404`, not a fallback to some default backend.
3. **Rate limiting** -- a Redis-backed token bucket per (site, IP), with an
   optional tighter bucket for specific paths (e.g. `/login`) to blunt
   credential-stuffing without throttling the whole site.
4. **Bot challenge** (optional, per site) -- a proof-of-work puzzle solved
   in-browser (or Cloudflare Turnstile, if you'd rather use a traditional
   CAPTCHA) before a page navigation is allowed through. Only applies to
   GET/HEAD requests that look like a browser loading a page -- see
   [SECURITY.md](SECURITY.md) for why that scope is deliberate.
5. **WAF inspection** -- path, query, headers, and body (form/JSON, up to
   2 MiB) are normalized (iterative percent-decoding) and matched against a
   scored rule set for SQL injection, XSS, command injection, and path
   traversal. A request's score determines whether it's blocked.
6. **Forward** -- clean traffic is reverse-proxied to your upstream, with
   `X-Forwarded-For`/`X-Real-IP` always set from the WAF's own
   determination of the client IP (never trusted verbatim from the
   incoming request, which would let an attacker spoof their way past rate
   limits and IP blocks).

Every step that finds something worth recording writes to an async,
bounded queue rather than blocking the response on a database write --
see [SECURITY.md](SECURITY.md) for why.

## Configuration

Sites, rate limits, bot-challenge settings, and sensitive paths are all
configured through the dashboard (or the REST API directly). Everything
else is environment variables, set in `.env`:

| Variable | Required | Purpose |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | yes | Database credentials |
| `REDIS_PASSWORD` | yes | Redis auth (the WAF refuses to start against a passwordless Redis) |
| `WAF_SECRET_KEY` | yes | 32+ random bytes (`openssl rand -hex 32`); signs CSRF tokens and bot-challenge nonces |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | no | Bootstrap admin account; if blank, a random password is generated and logged once |
| `PROXY_HTTP_PORT` / `PROXY_HTTPS_PORT` / `ADMIN_PORT` | no | Host-side port mappings (defaults: 80, 443, 9000) |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` / `PROXY_HTTPS_ADDR` | no | Serve HTTPS directly; see below |
| `TRUSTED_PROXIES` | no | CIDRs allowed to set `X-Forwarded-For` (your CDN/LB, if any) |
| `FAIL_OPEN_ON_INFRA_ERROR` | no | If Redis is unreachable, allow traffic through rather than block everything (default `false`... see note below) |
| `COOKIE_SECURE` | no | Set `false` only for local HTTP-only development |

### TLS

This WAF terminates TLS itself if you give it a certificate, or you can run
it behind your own TLS-terminating load balancer / reverse proxy and leave
it on plain HTTP internally. There's no built-in ACME/Let's Encrypt client
by design (see [SECURITY.md](SECURITY.md)) -- obtain a certificate however
you like (`certbot`, your cloud provider, an existing reverse proxy) and:

```bash
mkdir -p certs
cp /path/to/fullchain.pem certs/
cp /path/to/privkey.pem certs/
```

Then in `.env`:

```bash
TLS_CERT_FILE=/certs/fullchain.pem
TLS_KEY_FILE=/certs/privkey.pem
PROXY_HTTPS_ADDR=:8443
```

### Securing the admin panel

`docker-compose.yml` binds the admin port to `127.0.0.1` on the host, so by
default it is **not reachable from outside the machine it runs on**. To
manage it remotely, do one of:

- SSH tunnel: `ssh -L 9000:localhost:9000 your-server`, then open
  `http://localhost:9000` locally.
- A WireGuard/VPN connection to the host's private network.
- Put a TLS-terminating reverse proxy in front of `127.0.0.1:9000` on a
  separate hostname, itself behind IP allowlisting if possible.

Do not simply change the compose file's admin port binding to `0.0.0.0`
without one of the above -- the admin panel is a full authentication
surface and deserves the same caution as any other admin login page on the
internet.

## Admin API

The dashboard is a thin client over a REST API you can also call directly
(for automation, CI, etc). All endpoints except `/api/auth/login` require a
valid session cookie, and all state-changing requests need the
`X-CSRF-Token` header set to the value of the `_waf_csrf` cookie issued at
login (double-submit CSRF protection).

| Endpoint | Purpose |
|---|---|
| `POST /api/auth/login` | `{email, password}` → sets session + CSRF cookies |
| `POST /api/auth/logout` | Destroys the current session |
| `GET /api/auth/me` | Current user |
| `POST /api/auth/change-password` | `{current_password, new_password}` |
| `GET/POST /api/sites` | List / create protected sites |
| `GET/PUT/DELETE /api/sites/{id}` | Fetch / update / remove a site |
| `GET /api/logs` | Paginated attack logs; filter by `site_id`, `category`, `action`, `client_ip`, `since`, `until` |
| `GET /api/stats/summary?hours=24` | Dashboard overview data |
| `GET /healthz` | Liveness check (used by Docker) |

## Local development (without Docker)

Requires Go 1.22+, Node 20+, and your own Postgres/Redis (or run just those
two via `docker compose up postgres redis`).

```bash
# backend
go run ./cmd/waf   # needs the same env vars as above, e.g. via `export $(cat .env | xargs)`

# frontend, in another terminal (proxies /api to :9000 automatically)
cd web && npm install && npm run dev
```

To have `go run` serve the *real* dashboard instead of the placeholder
page:

```bash
cd web && npm install && npm run build
cp -r dist/* ../internal/webui/dist/
```

Run the test suite (this project has real unit tests for the security-
critical parts -- password hashing verified against Node's crypto, the
detection engine against real attack payloads and false-positive
guardrails, the PoW challenge end to end):

```bash
go test ./...
```

## Project structure

```
cmd/waf/            entrypoint: wires config, storage, proxy, and admin API together
internal/
  config/           environment variable loading + validation (fails fast on weak/missing secrets)
  security/         password hashing (PBKDF2-HMAC-SHA256), random tokens, HMAC signing
  store/            Postgres access -- schema, sites, users, attack logs (all parameterized queries)
  cache/             Redis client
  ratelimit/        token-bucket rate limiter + IP quarantine
  detection/        the WAF rule engine (SQLi/XSS/CmdI/path traversal)
  challenge/        proof-of-work bot challenge + optional Turnstile integration
  proxy/            the reverse proxy and its request pipeline
  api/              admin REST API (auth, sites, logs, stats)
  webui/            embeds the built dashboard into the Go binary
  httpx/            shared client-IP resolution (trusted-proxy aware)
web/                the dashboard (React + TypeScript + Tailwind)
Dockerfile          multi-stage: build dashboard -> build Go binary -> minimal distroless runtime
docker-compose.yml  waf + postgres + redis
```
