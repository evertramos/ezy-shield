---
title: Dashboard
description: Web dashboard for monitoring and control
order: 1
---

# Dashboard

The EzyShield dashboard is a small web UI that runs alongside the daemon and
gives operators a browser view of daemon state, active bans, strike history,
allowlist and logs.

**Status:** Phase 1 — authentication scaffold only. The live views, manual
ban/unban and WebSocket log tail land in later phases (issue #56).

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
ezyshield dashboard --addr 127.0.0.1:9091 --auth-db /tmp/auth.db
```

If `config.yaml` is missing, the dashboard falls back to `127.0.0.1:9090`
and `/var/lib/ezyshield/dashboard.db` so operators can dogfood before the
daemon is fully initialised.

---

## Routes

| Method | Path      | Auth      | Notes                                       |
|--------|-----------|-----------|---------------------------------------------|
| GET    | `/login`  | none      | Login form                                  |
| POST   | `/login`  | none      | Form submit; sets session cookie on success |
| POST   | `/logout` | none      | Clears session cookie                       |
| GET    | `/`       | required  | Placeholder index (Phase 2 will replace)    |

Unauthenticated requests to `/` receive a `303 See Other` to `/login`.

Session cookies:
- name `ezyshield_dashboard`,
- 32-byte hex token from `crypto/rand` (256 bits of entropy),
- `HttpOnly`, `SameSite=Strict`,
- sliding 30-minute inactivity timeout,
- stored **in memory only** — daemon restart forces re-login.

Cookies are not marked `Secure` because the dashboard is served over plain
HTTP on loopback; TLS, if required, terminates in the operator-managed
tunnel (Cloudflare, SSH, reverse proxy).

---

## Security posture

- **Bind guard:** loopback-only, enforced twice (construction and start).
- **Password storage:** PBKDF2-SHA256, 600 000 iterations, per-hash random
  salt, constant-time comparison.
- **Enumeration guard:** the login handler returns the same 401 response
  and message for unknown username and wrong password.
- **Session store:** in-memory, mutex-protected, opaque token, sliding
  expiry.
- **Templates:** rendered with `html/template`; any operator-supplied string
  goes through auto-escaping.
- **Auth DB permissions:** parent dir created with `0700`, file `chmod 0600`
  after schema apply.

Phase 2 additions (not yet implemented): CSRF token on state-changing routes,
audit log for every write operation, session limits per account.
