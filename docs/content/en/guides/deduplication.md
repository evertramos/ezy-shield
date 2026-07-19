---
title: Strike Deduplication
description: Understand how EzyShield avoids redundant bans
order: 3
---

# Active-Ban Deduplication

## Overview

While an IP has an active ban, EzyShield suppresses redundant strike and
enforcer writes for that IP. Traffic that keeps arriving from an
already-banned address does not escalate the strike ladder, does not issue
duplicate firewall rules, and does not flood the audit log.

## Semantics

A **strike** is one *attack episode*, not one malicious request. The
deduplication guard enforces this boundary:

| Scenario | Engine behaviour |
|---|---|
| Fresh IP crosses `ban_threshold` | Strike #1 recorded; 5-minute ban applied |
| Same IP re-hits while ban is active | Suppressed: no new strike, no enforcer call; the offender's `last_seen` is bumped only |
| Active ban expires | Next hit records strike #2 (1-hour ban) |
| IP reaches permanent ban (strike #5, TTL=0) | Suppressed forever — permanent bans never expire |
| Daemon restart | Suppression resumes from the persisted ban store (SQLite); no in-memory state required |

## Action `Op` values

| `Op` value | Meaning |
|---|---|
| `"ban"` | Strike recorded; enforcer called; ban active |
| `"dry_ban"` | Would ban; `armed=false`; no writes |
| `"already_banned"` | Suppressed: IP already has an active ban; only `last_seen` bumped |
| `"notify_only"` | Score in observe band; no ban |
| `"record"` | Below observe threshold, or allowlisted |

## What `total_strikes` measures

An offender's `total_strikes` counts distinct attack episodes — the number
of times an IP came back and attacked after a cooling-off period — not raw
malicious requests. A scanner burst of 60 requests in 66 seconds is one
strike, not 60. This makes the field a meaningful recidivism indicator.

## Burst vs Sustained Detection Tiers

EzyShield uses a two-tier detection model to catch both rapid attackers and "low & slow" scanners:

### Burst Tier (60-second window)

**Purpose**: Catch rapid attacks in concentrated bursts.

**Examples**:
- WordPress scanner hitting `/wp-login.php` 3+ times in 60 seconds
- SSH brute force: 5+ failed logins in 60 seconds
- HTTP scanner: 20+ 404 responses in 60 seconds

**Tuning**: Conservative thresholds optimized for high confidence. False positives are rare.

### Sustained Tier (1-hour window)

**Purpose**: Catch attackers who spread their probes across hours ("low & slow" strategy).

**Real-world example**: An attacker targeting WordPress with 30 login attempts across 6 hours in 2–3 hit bursts. Each burst falls below the burst-tier threshold (3 hits/min) but accumulates 10+ hits in 1 hour, triggering sustained detection.

**Examples**:
- WordPress: 10+ `/wp-login` hits spread across 1 hour
- XML-RPC abuse: 8+ `/xmlrpc.php` probes across 1 hour
- HTTP scanning: 60+ distinct 404s across 1 hour
- SSH: 10+ failed logins across 1 hour

**Tuning**: Thresholds are set conservatively to avoid legitimate user activity:
- An admin who logs into WordPress 3–4 times per hour will not trigger
- An automated backup script making periodic requests will not trigger
- Legitimate crawlers hitting 404 occasionally will not trigger

### How They Work Together

1. **Burst rule fires first**: Catches aggressive probers immediately
2. **Sustained rule fires later**: Catches patient attackers that slip through
3. **Deduplication prevents double-banning**: Once an IP has an active ban, sustained hits are suppressed (see Active-Ban Deduplication above)

### Adjusting Thresholds

To customize thresholds, point `rules_path` in config.yaml at your own rules file (start from the shipped `/etc/ezyshield/rules.yaml.example`) and adjust the `window` and `threshold` fields — the built-in rules are embedded in the binary, so editing repo files has no effect on an installed daemon:

```yaml
- name: http_wp_probe_sustained
  window: 3600s        # 1 hour
  threshold: 10        # adjust for your environment
  score: 75
```

**Guidelines**:
- Increase threshold if legitimate users are triggering the rule
- Decrease threshold if you're seeing low & slow attacks bypassing detection
- Keep burst and sustained thresholds separate; they catch different patterns

## Exploit Probe Detection (Immediate Verdict)

EzyShield includes a third detection tier for known RCE and exploit paths that have **zero legitimate use**:

### http_rce_probe Rule

**Purpose**: Immediate detection of known-exploit paths.

**Threshold**: 1 (single request triggers)  
**Score**: 95 (bypasses ambiguous band; rules always win)  
**Category**: `exploit_probe`

**Detected paths**: `phpunit`, `.git`, `.aws`, actuator endpoints, WordPress plugin shells, Terraform state, etc. (`.env` probes are covered by the separate `http_env_probe` rule.)

**Why threshold=1**: These paths have zero legitimate use in production. A single request to `/.git/config` is always suspicious.

**Why score=95**: Placed above the ambiguous band, so the decision engine never consults AI — the rules verdict is final.

**No double-ban risk**: Exploit probes trigger instantly with score=95, so they enter the ban store before any burst-tier rule. Subsequent hits are suppressed by deduplication.

### Related exploit detection

Other rules targeting low-frequency errors that may indicate scanning:
- `http_scanner_400`: 10+ malformed requests (threshold=10, score=60)
- `http_scanner_503`: 15+ service unavailable responses (threshold=15, score=65)

These operate on the burst tier and allow more requests before triggering, since occasional 400/503 is legitimate.

## Related

- [Getting started](../getting-started/index.md): strike table and ban escalation ladder
