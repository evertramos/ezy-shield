---
title: Vaultwarden
description: Protecting a Vaultwarden password vault from brute force
order: 14
---

# Protecting Vaultwarden

A password vault is a prime brute-force target. EzyShield parses Vaultwarden's default log format and ships rules that ban credential and 2FA guessing.

## What gets detected

`vaultwarden_auth_fail` events, from two line shapes:

- `Username or password is incorrect. Try again. IP: <ip>. Username: <user>.` — password failures (username captured, capped, treated as untrusted).
- `Invalid TOTP code! … IP: <ip>` — the 2FA variant (`mfa=totp` field).

Built-in rules: `vaultwarden_bruteforce` (5 failures / 5 min, score 85) and `vaultwarden_bruteforce_sustained` (10 / 1 h, score 80). Tune via `rules.d` drop-ins.

## Collectors

Docker (the common deployment — the parser recognizes containers named `*vaultwarden*` automatically, and unwraps docker's json-file format):

```yaml
collectors:
  - kind: docker
    container: vaultwarden        # parser auto-routed by name; or add `parser: vaultwarden`
```

File-based (`LOG_FILE=/var/log/vaultwarden.log`):

```yaml
  - kind: file
    path: /var/log/vaultwarden.log   # routes to the vaultwarden parser by name
```

## The reverse-proxy caveat (read this)

Vaultwarden almost always sits behind nginx/caddy/traefik. **If Vaultwarden is not configured to trust the proxy's forwarded headers, the IP in its log is the proxy's own address** — and banning it would block the proxy itself (EzyShield's allowlist/anti-lockout will usually refuse localhost, but a docker-network proxy IP may not be covered).

- Right fix: set Vaultwarden's reverse-proxy support (e.g. `IP_HEADER=X-Real-IP`) so its log carries the real client IP — then this parser is the best source.
- Alternative: skip Vaultwarden's log and let the **proxy's** access log (nginx/caddy/traefik parser) do the detection — login brute force shows up there as repeated `POST /identity/connect/token` traffic, covered by the HTTP rules.
- Sanity check: run in dry-run and `ezyshield watch` — if every detection shows the same internal IP, you're seeing the proxy.

## Rollout

As always: dry-run first, allowlist your own networks, watch a day of decisions, then `ezyshield arm`.
