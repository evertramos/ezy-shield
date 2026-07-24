---
title: Dashboard
description: Web dashboard for monitoring and control
order: 1
---

# Dashboard

The EzyShield dashboard is a small web UI that runs alongside the
daemon. It gives operators a browser view of daemon state, active
bans, allowlist entries, the recent audit trail and the strike
timeline, plus in-page controls for manual ban / unban / allow.

**Status: Phase 4 (final).** Authentication, live views, event log,
strike timeline, WebSocket live updates, CSRF-protected write forms,
per-account login throttle and a per-user session cap. Server-side
redaction and multi-user RBAC are explicitly out of scope for this
release.

---

## Localhost-only architecture

The dashboard binds **exclusively to a loopback address** — `127.0.0.1`,
`::1` or the literal `localhost`. Any other bind (`0.0.0.0`, a public
interface, etc.) is refused at startup, both in
`internal/dashboard.New()` and again in `Server.Run()`. This is a hard
rule from `AGENTS.md §2` and `docs/internal/SECURITY-REVIEW.md §6`. The
dashboard is therefore reachable only from the same host, and remote
access is by design an *operator concern* handled outside the daemon.

For remote access see the companion guide:
[Remote access to the dashboard](../guides/dashboard-remote-access.md).
The short version:

- **SSH port-forward** is the simplest option and needs nothing extra
  on the server.
- **Cloudflare Tunnel** or **Tailscale** give you a persistent path
  without opening ports.
- Do **not** run the dashboard behind a `--network=host` container
  that publishes to a public interface, and do **not** put `0.0.0.0`
  in the config — the guard will refuse to start.

---

## Installation and first run

Nothing special — the dashboard ships in the same binary. First-run
bootstrap happens on the very first `ezyshield dashboard` startup:

1. It generates a random password (18 random bytes → 24 URL-safe
   base64 chars).
2. It stores the PBKDF2-SHA256 hash (600 000 iterations, per-hash
   16-byte salt) in `<data_dir>/dashboard.db` (mode `0600`).
3. It prints the plaintext password **exactly once** to standard
   error:

   ```
   ======================================================================
   EzyShield dashboard: admin account created.
     Username: admin
     Password: 2yQ7c1p...
   STORE THIS PASSWORD NOW — it will not be shown again.
   To rotate the password, delete the auth DB and restart:
     rm /var/lib/ezyshield/dashboard.db
   ======================================================================
   ```

On an interactive terminal the plaintext password never touches disk.
If you miss the banner, delete `dashboard.db` and restart — a fresh
account will be generated.

**Non-interactive stderr (systemd, Docker, cron).** When stderr is not
a terminal — the common case for the documented install path — the
banner above isn't printed, because it would otherwise be captured
verbatim by journald or `docker logs`. Instead, the plaintext password
is written once to `<data_dir>/dashboard.first-run-password` (mode
`0600`), and only that file path is printed to stderr:

```
EzyShield dashboard: admin account created (username: admin).
stderr is not a terminal — the initial password was written to:
  /var/lib/ezyshield/dashboard.first-run-password (mode 0600)
Read it once and remove it:
  sudo cat /var/lib/ezyshield/dashboard.first-run-password && sudo rm /var/lib/ezyshield/dashboard.first-run-password
```

Read the file once and delete it — it is not removed automatically.

---

## Configuration

The dashboard is opt-in via the `dashboard:` block in `config.yaml`:

```yaml
data_dir: /var/lib/ezyshield

# Daemon control socket — reused by CLI verbs (status, ban, list, ...)
# and by the dashboard when it needs live data. Defaults to
# /run/ezyshield/ezyshield.sock.
socket_path: /run/ezyshield/ezyshield.sock

dashboard:
  # Bind address. Must resolve to a loopback address; anything else
  # is refused at startup.
  addr: 127.0.0.1:9090

  # SQLite file for the admin credential hash. Optional; defaults to
  # <data_dir>/dashboard.db.
  auth_db_path: /var/lib/ezyshield/dashboard.db
```

CLI flags override config values:

```bash
ezyshield dashboard \
  --addr 127.0.0.1:9091 \
  --auth-db /tmp/auth.db \
  --socket /run/ezyshield/ezyshield.sock
```

If `config.yaml` is missing, the dashboard falls back to
`127.0.0.1:9090`, `/var/lib/ezyshield/dashboard.db` and the default
daemon socket path so operators can dogfood before the daemon is fully
initialised. When the daemon socket is unreachable every page still
renders — with a graceful "Daemon is offline" banner instead of live
data.

---

## Pages and features

| Method | Path                     | Auth       | Notes                                                        |
|--------|--------------------------|------------|--------------------------------------------------------------|
| GET    | `/login`                 | none       | Login form                                                   |
| POST   | `/login`                 | none       | Form submit; sets session cookie on success                  |
| POST   | `/logout`                | required   | CSRF-protected like every mutation; clears the session       |
| GET    | `/`                      | required   | Redirects authed sessions to `/dashboard`                    |
| GET    | `/dashboard`             | required   | Status overview: daemon state, mode, uptime, version, active-ban count, per-strike breakdown |
| GET    | `/dashboard/bans`        | required   | Table of active bans with per-row unban action + manual ban form |
| GET    | `/dashboard/allowlist`   | required   | Table of allowlist entries + add-entry form                  |
| GET    | `/dashboard/events`      | required   | Table of the last 100 `audit_log` rows; live-updates via WebSocket |
| GET    | `/dashboard/timeline`    | required   | Per-IP 5-strike ladder reconstructed from `list` + `events`  |
| GET    | `/dashboard/ws`          | required   | WebSocket upgrade; pushes audit / refresh envelopes          |
| POST   | `/dashboard/ban`         | required   | Manual ban action; redirects to `/dashboard/bans`             |
| POST   | `/dashboard/unban`       | required   | Manual unban action; redirects to `/dashboard/bans`           |
| POST   | `/dashboard/allow`       | required   | Add-to-allowlist action; redirects to `/dashboard/allowlist`  |

Unauthenticated requests to any authed route receive a `303 See Other`
to `/login`.

### Layout & UI

- Sticky top nav with an active-page underline.
- Responsive layout: single-column on narrow screens, two-column
  bans/allowlist on desktop. Tables gain a horizontal scroller
  automatically on mobile.
- Light and dark mode via `prefers-color-scheme` (no toggle — the
  browser decides).
- Success and error banners auto-dismiss after 5 s. The persistent
  "daemon offline" warning is intentionally not dismissed.

### Flash codes

Every write action returns a `303` back to the source page with an
`ok=…` or `err=…` query-string flash code. Only the codes below are
rendered; anything else is silently ignored so crafted URLs cannot
inject arbitrary strings into the UI.

| Flash code       | Meaning                                                       |
|------------------|---------------------------------------------------------------|
| `ban-queued`     | Ban was accepted by the daemon                                |
| `unban-queued`   | Unban was accepted by the daemon                              |
| `allow-added`    | Allowlist entry was accepted by the daemon                    |
| `missing-ip`     | The `ip` field was empty                                      |
| `invalid-ip`     | The `ip` field could not be parsed as an IP or CIDR (`netip`) |
| `bad-form`       | Malformed form submission                                     |
| `daemon-error`   | Daemon reachable but returned a non-OK response               |
| `daemon-offline` | Daemon unix socket did not accept the connection              |

### Live updates (`/dashboard/ws`)

Every page runs a small script that opens a WebSocket to
`/dashboard/ws`. The endpoint is guarded by the same session cookie as
every other `/dashboard` route: an unauthenticated upgrade attempt is
turned into a `303 See Other` to `/login`.

The dashboard uses a **polling event bus** rather than a daemon-side
push: every 3 seconds it calls the daemon `events` RPC, diffs the
result against the highest `audit_log.id` it has already seen, and
broadcasts the diff to each connected client. This trades sub-second
latency for a very small blast radius — no changes to the daemon
control API, no long-lived reader on the socket, and no memory of
subscribers on the daemon side.

Wire envelope (JSON, always UTF-8 text frames):

```json
{"type": "hello"}
{"type": "audit",   "entry": {"id": 42, "recorded_at": "2026-07-08T02:15:00Z", "op": "ban", "ip": "203.0.113.7", "ttl_seconds": 300, "strike": 1, "reason": "sshd"}}
{"type": "refresh"}
```

When a poll cycle finds more than 10 new events the bus coalesces the
burst into one `refresh` message and the browser reloads the current
page. That cap plus the 3 s poll cadence keeps the per-client message
rate low without an unbounded burst of individual `audit` frames.

Reconnection is handled by the small `EzyLive` helper baked into the
layout: exponential back-off starting at 1 s and capped at 30 s, with
a "live" dot in the header that turns green when the socket is open.

### `/dashboard/events`

Server-rendered table of the last 100 `audit_log` rows (newest first),
identical schema to the `entry` object above. The per-page script
listens on `EzyLive.on('audit', …)` and prepends new rows without a
page reload, deduping by `data-audit-id`. The DOM is capped at 100
rows so a long-running tab does not grow without bound.

### `/dashboard/timeline`

One card per currently-banned IP with the 5-strike ladder
reconstructed from the recent audit trail:

- Each step is one strike level (1 → 5).
- Reached steps are highlighted; the current tier is outlined.
- Timestamps and reasons come straight from the `audit_log` rows.
- When the audit window truncated before an earlier escalation, the
  step still renders as reached (the current `bans_active` row is
  authoritative) but without a timestamp.

Read-only — no forms.

---

## Security model

### Authentication

- Passwords are hashed with **PBKDF2-SHA256, 600 000 iterations**,
  per-hash 16-byte random salt. Verification uses constant-time
  comparison.
- On login, the unknown-username path runs `verifyPassword` against a
  server-side decoy hash so response time does not distinguish
  existing accounts from missing ones (CWE-208).
- Session cookies: name `ezyshield_dashboard`, 32-byte hex token from
  `crypto/rand` (256 bits of entropy), `HttpOnly`, `Secure`,
  `SameSite=Strict`, sliding 30-minute inactivity timeout, kept
  **in memory only** — restarting the dashboard process forces re-login.
- `Secure` is set even on the default loopback deployment: modern
  browsers treat `http://localhost` as a secure context, so the
  cookie still round-trips on plaintext localhost, and any
  TLS-terminated reverse proxy in front benefits from browser refusal
  on plaintext downgrade.

### CSRF protection

- Every session carries an independent 32-byte CSRF token, generated
  by `crypto/rand` at login time and stored on the session entry.
- Every server-rendered POST form embeds the token in a hidden
  `csrf_token` input, including logout and the per-row Unban buttons.
- All POST handlers validate the token in **constant time** via
  `crypto/subtle.ConstantTimeCompare` before touching the daemon
  socket. Missing / mismatched tokens produce `403 Forbidden` with
  no side effect.
- A stolen cookie alone is therefore not enough to mount a
  cross-site request forgery, and `SameSite=Strict` blocks the
  browser from sending the cookie on cross-site POST anyway.

### Login rate limit

- Failed logins are counted per-account (username), not per source
  IP: on a loopback binding every client already collapses to
  `127.0.0.1`, and a distant attacker rotating tunnels would bypass
  an IP-keyed limit.
- **5 failed attempts inside a 60 s sliding window** trip a **60 s
  lockout**. During the lockout the login handler returns
  `429 Too Many Requests` with a fixed banner, without hitting the
  password store — no PBKDF2 CPU is burned on brute-force attempts.
- A successful login clears the tally immediately.
- The counter is in-memory only; a daemon restart resets every
  lockout, which is intentional given the single-node scope.

### Session management

- The store caps live sessions at **3 per account**. A fourth login
  evicts the oldest slot silently, so a stolen cookie has a bounded
  useful life and a shared machine can't accumulate abandoned
  sessions.
- The cap is per-username: `alice`'s session is unaffected by
  `bob` hitting his cap.
- Any authenticated request slides the expiry forward by the
  configured 30-minute idle timeout.

### Input validation

- Ban / unban / allow POST handlers parse the `ip` field with
  `netip.ParsePrefix` (falling back to `netip.ParseAddr` → /32 or
  /128) *before* any daemon RPC — hostnames, oversized strings and
  garbage characters are rejected at the dashboard edge
  (`SECURITY-REVIEW.md §1`).
- Operator-supplied reasons are prefixed with `dashboard:admin` so
  the daemon's `audit_log` distinguishes dashboard writes from CLI
  verbs. Empty reason produces the bare tag; filled reason produces
  `dashboard:admin: <text>`.
- All operator strings are rendered through `html/template`, which
  auto-escapes on output — no `fmt.Sprintf`-into-HTML anywhere in
  the templates.

### Auth DB permissions

- Parent directory: `0700`.
- SQLite file: `chmod 0600` after schema apply.

### RPC and offline handling

- Dashboard-initiated daemon calls run with a **2-second context
  timeout**, so a hung daemon does not stall the browser.
- Every page and every write handler distinguishes
  `daemon.ErrDaemonUnreachable` from a daemon-level error, rendering
  an offline banner (reads) or a `daemon-offline` flash code
  (writes) instead of surfacing a raw dial error.

### WebSocket security

- The upgrade goes through the identical `requireAuth` middleware
  as every other `/dashboard` route — an unauthenticated tab
  becomes a `303 See Other` to `/login`.
- Same-origin check is enforced by the library at handshake time.
- No secrets or raw log lines cross the socket; only `audit_log`
  rows the daemon already wrote through parameterised INSERTs.

---

## Troubleshooting

**"Daemon is offline" banner on every page.** The dashboard could not
reach the daemon control socket. Confirm the daemon is running
(`systemctl status ezyshield` or `ezyshield run` in a shell), that
`socket_path` in `config.yaml` matches what the daemon uses, and that
the dashboard user is in the `ezyshield` group (the socket is mode
`0660`).

**Lost the admin password.** Delete the auth DB and restart the
dashboard:

```bash
rm /var/lib/ezyshield/dashboard.db
ezyshield dashboard
```

The next startup regenerates a fresh admin account and prints the
password. All existing sessions are invalidated. Do this on the
server, not through the dashboard — if you're locked out of the UI
you need shell access anyway.

**"Too many failed attempts" on login.** The account is in the 60 s
lockout after 5 wrong passwords. Wait 60 s. If the lockout keeps
tripping unexpectedly, restart the dashboard process to clear the
in-memory counter.

**Session expired / kicked out.** Sessions are in-memory and slide
forward on activity. If you closed the tab and reopened it 45 min
later the session may have timed out (30 min idle). If you logged in
elsewhere and are now on the 4th session, the oldest was evicted — log
in again on this browser.

**Timeline shows steps without timestamps.** The audit trail only
holds the recent window (last 500 rows for timeline reconstruction).
If an IP escalated before that window, the current tier still shows
as reached from `bans_active`, but the timestamp is missing. This is
expected behaviour, not a bug.

**"Forbidden" (403) after submitting a form.** Almost always a CSRF
mismatch. The likely cause is a browser tab from before a login
(stale CSRF), a script or bot that scraped the form and posted it
later, or a proxy stripping form fields. Reload the page to fetch a
fresh token and retry.
