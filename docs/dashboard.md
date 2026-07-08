# Dashboard

The EzyShield dashboard is a small web UI that runs alongside the daemon and
gives operators a browser view of daemon state, active bans, strike history,
allowlist and logs.

**Status:** Phase 2 — authentication, live status, active-bans and
allowlist pages, plus manual ban / unban / allow POST actions. Real-time
WebSocket log tail lands in Phase 3 (issue #56).

---

## Localhost-only architecture

The dashboard binds **exclusively to a loopback address** — `127.0.0.1`, `::1`
or the literal `localhost`. Any other bind (`0.0.0.0`, a public interface,
etc.) is refused at startup, both in `internal/dashboard.New()` and again in
`Server.Run()`.

This is a hard rule from `AGENTS.md §2` (“No new listeners on 0.0.0.0”) and
from `docs/SECURITY-REVIEW.md §6` (control surfaces). The dashboard is
therefore reachable only from the same host, and remote access is by design
an *operator concern* handled outside the daemon.

### Remote access — recommended patterns

Both patterns terminate outside `ezyshield`; the dashboard process still sees
only local connections.

- **SSH port-forward (simplest, no extra service).** From your workstation:

  ```bash
  ssh -L 9090:127.0.0.1:9090 operator@server.example.com
  # then open http://localhost:9090 in your browser
  ```

- **Cloudflare Tunnel (persistent, no open ports).** `cloudflared` runs on
  the server, opens an outbound tunnel and publishes the dashboard behind
  Cloudflare Access. The dashboard still binds only to `127.0.0.1` on the
  server; `cloudflared` is the only process aware of Cloudflare.

Do **not** run the dashboard behind a `--network=host` container that
forwards to a public interface, and do **not** put `0.0.0.0` in the config —
the guard will refuse to start.

---

## First-run bootstrap

On the very first `ezyshield dashboard` startup, if no admin account exists
in the auth store, EzyShield:

1. generates a random password (18 random bytes → 24 URL-safe base64 chars),
2. stores its PBKDF2-SHA256 hash (600 000 iterations, per-user 16-byte salt)
   in `<data_dir>/dashboard.db` (mode `0600`),
3. prints the plaintext password **exactly once** to standard error.

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

The plaintext password never touches disk. If you miss the banner, delete
`dashboard.db` and restart `ezyshield dashboard` — a fresh account will be
generated.

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

If `config.yaml` is missing, the dashboard falls back to `127.0.0.1:9090`,
`/var/lib/ezyshield/dashboard.db`, and the default daemon socket path so
operators can dogfood before the daemon is fully initialised. When the
daemon socket is unreachable the dashboard still renders — every page
shows a graceful "Daemon is offline" banner instead of live data.

---

## Routes

| Method | Path                     | Auth       | Notes                                                        |
|--------|--------------------------|------------|--------------------------------------------------------------|
| GET    | `/login`                 | none       | Login form                                                   |
| POST   | `/login`                 | none       | Form submit; sets session cookie on success                  |
| POST   | `/logout`                | none       | Clears session cookie                                        |
| GET    | `/`                      | required   | Redirects authed sessions to `/dashboard`                    |
| GET    | `/dashboard`             | required   | Status overview: daemon state, mode, uptime, version, active-ban count, per-strike breakdown |
| GET    | `/dashboard/bans`        | required   | Table of active bans with per-row unban action + manual ban form |
| GET    | `/dashboard/allowlist`   | required   | Table of allowlist entries + add-entry form                  |
| POST   | `/dashboard/ban`         | required   | Manual ban action; redirects to `/dashboard/bans`             |
| POST   | `/dashboard/unban`       | required   | Manual unban action; redirects to `/dashboard/bans`           |
| POST   | `/dashboard/allow`       | required   | Add-to-allowlist action; redirects to `/dashboard/allowlist`  |

Unauthenticated requests to any authed route receive a `303 See Other` to
`/login`.

Every write action returns a `303` back to the source page with an `ok=…`
or `err=…` query-string flash code. Only the codes listed below are
rendered; anything else is silently ignored so crafted URLs cannot inject
arbitrary strings into the UI.

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

Session cookies:
- name `ezyshield_dashboard`,
- 32-byte hex token from `crypto/rand` (256 bits of entropy),
- `HttpOnly`, `Secure`, `SameSite=Strict`,
- sliding 30-minute inactivity timeout,
- stored **in memory only** — daemon restart forces re-login.

`Secure` is set even though the default loopback deployment is plain HTTP:
modern browsers treat `http://localhost` as a secure context and still
deliver the cookie, while operators fronting the dashboard with TLS
through a reverse proxy or Cloudflare Tunnel benefit from browser refusal
on plaintext downgrade.

---

## Security posture

- **Bind guard:** loopback-only, enforced twice (construction and start).
- **Password storage:** PBKDF2-SHA256, 600 000 iterations, per-hash random
  salt, constant-time comparison.
- **Enumeration guard:** the login handler runs the same PBKDF2 work
  against a decoy hash on the unknown-username path, so unknown-user and
  wrong-password requests are indistinguishable by wall-clock time
  (CWE-208).
- **Session store:** in-memory, mutex-protected, opaque token, sliding
  expiry.
- **Templates:** rendered with `html/template`; every operator-supplied
  string — reason notes, IP inputs echoed on error — goes through
  auto-escaping.
- **Input validation on write actions:** the `ip` form field is parsed
  with `netip.ParsePrefix` (falling back to `netip.ParseAddr`) *before*
  any daemon RPC is issued, so hostnames, oversized strings and invalid
  characters are rejected at the dashboard edge (`SECURITY-REVIEW.md §1`).
- **Auth DB permissions:** parent dir created with `0700`, file `chmod 0600`
  after schema apply.
- **RPC budget:** dashboard-initiated daemon calls run with a 2-second
  context timeout so a hung daemon does not stall the browser.
- **Daemon-offline handling:** every page and every write handler
  differentiates `daemon.ErrDaemonUnreachable` from a daemon-level error,
  rendering an offline banner (reads) or a `daemon-offline` flash code
  (writes) instead of surfacing a raw dial error.

Phase 3 additions (not yet implemented): CSRF token on state-changing
routes, audit log for every write operation, session limits per account,
WebSocket log tail with server-side redaction.
