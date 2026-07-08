---
title: Security Overview
description: Public security posture and guarantees
order: 1
---

# Security Overview

This page describes EzyShield's security model from a user's perspective. For detailed threat analysis, see the internal SECURITY-REVIEW (available in the ezy-shield repository).

## Architecture

```
logs (SSH, Nginx)
  ↓
[ Collector ] — tail file, read journald
  ↓
[ Parser ] — structured event (IP, method, status)
  ↓
[ Rule Engine ] — offline scoring (always runs, no network)
  ↓
[ AI (optional) ] — Anthropic/OpenAI/Ollama (only for ambiguous events)
  ↓
[ Decision Engine ] — make ban/allow/defer decision
  ↓
[ Enforcer (privilege-separated) ] — apply bans (nftables, Cloudflare)
```

**Key principle: the main daemon never holds elevated privileges.** Firewall mutations only happen through a separate `ezyshield-enforcer` binary that holds `CAP_NET_ADMIN`.

## Anti-lockout guarantee

EzyShield has a hard rule: **your active SSH session and admin CIDRs can never be banned**, even if they match an attack pattern.

Before any ban is written to the firewall:

1. Detect the SSH peer IP from `SSH_CLIENT` env var
2. Check admin CIDRs from policy.yaml
3. If either matches the target IP, reject the ban

This is enforced in code, not a rule. No misconfigured threshold can lock you out.

## Allowlist supremacy

The allowlist is checked FIRST, before any rule engine decision. An allowlisted IP cannot be banned by any rule, AI decision, or manual ban attempt.

```yaml
allowlist:
  cidrs:
    - 10.0.0.0/8     # Internal network
  asns:
    - 1234           # Trusted ISP
```

## Rate limiting

A broken rule or poisoned feed cannot ban the entire internet. The `max_bans_per_minute` cap (default 30) queues excess bans for the next minute.

## Secret handling

No secrets appear in:
- Config files (use `env:VAR_NAME` syntax)
- Log output
- Error messages
- AI prompts
- Audit trail

API tokens are resolved once at startup and never printed. If a secret is referenced in an error, the error is rewritten to omit it.

## AI safety

When AI is enabled for ambiguous events (40–70 score):

1. **Schema validation**: AI output is parsed into a structured type; malformed responses cause a fallback decision.
2. **Policy clamping**: AI can only suggest within the ban thresholds and durations you configured. It cannot escalate beyond them.
3. **Audit trail**: Every AI decision is logged with the full AI response, so you can audit and override if needed.
4. **No prompt injection**: Log lines are passed as data, never interpolated into instructions. The prompt is fixed and controlled.

## Privilege separation

- **Main daemon** (`ezyshield`): runs as unprivileged user, reads logs, makes decisions, communicates via unix socket
- **Enforcer** (`ezyshield-enforcer`): holds `CAP_NET_ADMIN` only, accepts a fixed verb set (ban/unban/sync), mutates nftables in a safe, idempotent way

The enforcer is not a library. It's a separate process. The main daemon cannot directly modify the firewall.

## No network listeners

EzyShield does not open any TCP/UDP ports. Control is via:
- CLI: `ezyshield ban`, `ezyshield list`, etc. (local only)
- Unix socket: `/var/run/ezyshield/control.sock` (filesystem permissions)

## Audit trail

Every action is logged to SQLite:
- When: timestamp
- What: IP, rule, score, decision (ban/allow/defer)
- Why: rule name, AI response (if AI was consulted)
- How: which backend enforced it (nftables, Cloudflare, manual)

Export for compliance:

```bash
ezyshield list --audit --json > audit_log.json
```

## Cloudflare sync

When using Cloudflare Lists:

1. **Idempotent sync**: every 30 min, EzyShield reconciles its view with Cloudflare (adds new bans, removes expired ones)
2. **Source of truth**: `bans_active` table in SQLite is the source of truth. If EzyShield crashes and restarts, it will restore Cloudflare blocks from the DB.
3. **Non-ezyshield rules preserved**: EzyShield only touches rules tagged with `notes: "ezyshield: <ip>"`. Hand-created Cloudflare rules are left alone.

## Dry-run by default

`armed: false` is the default in `policy.yaml`. Enforcement is opt-in. You must explicitly set `armed: true` to start blocking.

Before arming, run in dry-run for 24+ hours and review decisions.

## Dependencies

EzyShield is a single static Go binary with minimal runtime dependencies:

- Linux kernel nftables (for local enforcement)
- Cloudflare API (optional, TLS verified)
- AI provider API (optional, TLS verified)

No Python, no Ruby, no Java runtime. No third-party packet inspection. No kernel modules.

## Threat model

**In scope (we protect against):**
- Brute-force SSH/RDP login attempts
- WordPress/Drupal login scanners
- Port scanners and service enumeration
- HTTP bots and scrapers
- Distributed attacks (botnet fingerprinting)

**Out of scope:**
- Kernel exploits
- Compromised SSH keys
- Application-layer logic bugs
- Insider threats
- AI provider compromise (we assume Anthropic/OpenAI API is trustworthy)

## Compliance

EzyShield maintains:
- Full audit trail (SQL queryable)
- No PII in logs (only IP addresses)
- Rate limiting to prevent denial-of-service
- Allowlist for whitelisted traffic
- Dry-run mode for testing before enforcement

Suitable for SOC 2, ISO 27001, and GDPR requirements where request logging is necessary.

## Reporting security issues

Found a vulnerability? Please report it to security@ezyshield.com (if available) or open a private security advisory on GitHub. Do not open a public issue.
