# Security posture

Read this before you deploy. The short version: this WAF adds a real,
meaningful layer of defense, built with care -- and it is still not a
substitute for a secure application behind it, and it cannot guarantee
"zero vulnerabilities." No WAF can, commercial or open source. Anyone who
tells you otherwise is selling something. This document explains what's
actually implemented, the reasoning behind specific choices, and -- most
importantly -- what this system does **not** protect against.

## What's implemented, and why

**Detection engine (SQLi / XSS / command injection / path traversal)**
Signature/heuristic matching with severity scoring (a request is blocked
when its cumulative score crosses a threshold, not on any single weak
match), over path, query, headers, and body (form/JSON, up to 2 MiB).
Input is normalized with iterative percent-decoding to catch
double/triple-encoding evasion. Matching uses Go's `regexp` package, which
is RE2-backed and therefore immune to catastrophic-backtracking ReDoS --
a hostile payload cannot make the detection engine itself hang, which is a
structural property of the engine, not a claim about each individual
pattern.

**Rate limiting & quarantine**
An atomic Redis-backed token bucket per (site, IP), with tighter,
independently-configurable limits for specific paths (e.g. `/login`).
Repeated violations escalate to a temporary IP-wide quarantine that short-
circuits before any rule evaluation runs.

**Bot defense**
A client-side proof-of-work challenge by default (no external account or
API key needed), or Cloudflare Turnstile if you configure it. Deliberately
scoped to GET/HEAD requests that look like a page load -- see "Scope
limitations" below.

**Admin authentication**
Passwords hashed with PBKDF2-HMAC-SHA256 at 600,000 iterations (OWASP's
current recommendation for that construction). Sessions are opaque random
tokens; only a SHA-256 hash of the token is stored server-side, so a
snapshot of Redis alone doesn't yield a usable session. CSRF is enforced
via double-submit cookie on top of `SameSite=Strict` session cookies. The
login endpoint has its own tight rate limit independent of the general API
limit, login failures are logged, and a failed login for a nonexistent
email takes deliberately similar time to a wrong password, to resist
account enumeration via timing. There is no hardcoded default account:
either you set `ADMIN_EMAIL`/`ADMIN_PASSWORD`, or a random password is
generated and shown exactly once in the startup logs.

**The WAF's own attack surface**
Every database query in this codebase is parameterized -- it would be a
particular kind of embarrassing for a tool whose entire purpose is
stopping SQL injection to be vulnerable to it internally. Dependencies are
kept deliberately minimal (`lib/pq` and `go-redis`, both with no further
transitive dependencies of consequence) to keep the supply-chain surface
small. The production container is built from `distroless/static`: no
shell, no package manager, nothing an attacker could use if they ever
landed code execution in the container. It runs as a non-root user. HTTP
servers have conservative header/body/timeout limits to resist slow-client
(Slowloris-style) exhaustion of the WAF itself.

**Fail-safe defaults**
A request that scores high enough to block does so regardless of a site's
`mode` field being empty or unexpected -- only an explicit "monitor" mode
downgrades enforcement to logging-only. An unrecognized `Host` header gets
a 404, never a fallback to some default backend.

## Scope limitations (by design)

- **Bot challenge only gates page navigations.** POST requests, JSON APIs,
  and webhooks are never shown a JS challenge (they couldn't solve it
  programmatically without breaking the integration). They're still fully
  covered by rate limiting and WAF inspection -- brute-force protection on
  something like a login POST endpoint comes from the sensitive-path rate
  limit, not the bot challenge.
- **No Unicode normalization.** Detection normalizes via percent-decoding
  and case-folding, not full NFKC/homoglyph normalization. This is a
  narrower gap than it might sound: SQL, JavaScript, and shell syntax all
  rely on specific ASCII keywords and metacharacters, so homoglyph
  substitution mostly breaks the payload's own syntax rather than evading
  detection -- but it is a real, known gap for anything relying on
  non-ASCII confusables.
- **File upload contents aren't deep-scanned.** Multipart form field
  *values* are inspected; the raw bytes of uploaded files are not, both to
  avoid false positives on arbitrary binary data and to keep large uploads
  fast. If your application processes uploaded files in dangerous ways
  (executing them, parsing them with a vulnerable library), this WAF does
  not compensate for that.
- **Rate limiting and quarantine are IP-based.** Clients behind a shared
  NAT or corporate proxy share a fate; a misconfigured `TRUSTED_PROXIES`
  (or none, with a CDN in front that you haven't told the WAF about) can
  make every visitor look like one IP, or make the WAF trust a spoofable
  header. Set `TRUSTED_PROXIES` correctly for your actual network topology.
- **Single-instance design.** This is built to run as one instance in
  front of your site(s), not as a horizontally-scaled fleet. The Redis-
  backed state would mostly work across replicas, but this hasn't been
  built or tested for that.

## What this is not

- **Not a substitute for secure application code.** Parameterized queries,
  output encoding, proper authentication and authorization, and keeping
  your own dependencies patched all remain entirely your responsibility.
  A WAF is a compensating control, not a fix for a vulnerability -- it
  reduces the window and the ease of exploitation, it doesn't close the
  hole.
- **Not immune to bypass.** Signature-based detection has an inherent
  false-negative rate against a sufficiently determined, creative
  attacker who tests encodings and payload variants against a copy of this
  exact rule set (which is open source -- assume a serious attacker has
  read it). This is true of every regex/signature-based WAF that exists,
  commercial included. The severity-scoring model and multiple detection
  layers raise the bar; they do not remove it.
- **Not a guarantee.** "High security" was the brief, and this was built
  to a high standard throughout -- parameterized queries, minimal
  dependencies, hashed and short-lived credentials, hardened HTTP servers,
  fail-safe defaults, extensive tests including against real attack
  payloads. None of that adds up to "no vulnerabilities." Treat this the
  way you'd treat any security-critical software you didn't write
  yourself: read the code, test it against your own traffic patterns in
  monitor mode before switching to block mode, and keep it updated.

## Recommendations

1. **Start new sites in `monitor` mode.** Watch the logs for a few days,
   confirm nothing legitimate is getting flagged, then switch to `block`.
2. **Get a real penetration test** for anything protecting sensitive data
   or transactions, from this WAF or any other.
3. **Keep dependencies current.** Run `go list -m -u all` and
   `npm audit` periodically; both dependency graphs are intentionally small
   specifically so this is cheap to stay on top of.
4. **Ship logs somewhere durable.** The structured JSON logs on stdout
   (`docker compose logs waf`) are your audit trail for admin actions and
   should be retained outside the container, not just relied on in
   Postgres.
5. **Don't treat this as your only layer.** For anything business-critical,
   pairing a self-hosted WAF like this with upstream protections (a CDN
   with its own DDoS mitigation, for instance) is more resilient than any
   single layer.
