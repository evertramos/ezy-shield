# Active-Ban Deduplication — EzyShield

## Overview

Since issue #28, `Engine.Decide` suppresses redundant strike/enforcer writes
when a target IP already has an active ban in `bans_active`.

## Semantics

A **strike** is one *attack episode*, not one malicious request. The
deduplication guard enforces this boundary:

| Scenario | Engine behaviour |
|---|---|
| Fresh IP crosses `ban_threshold` | Strike #1 recorded; 5-minute ban applied |
| Same IP re-hits while ban is active | Suppressed: no new strike, no enforcer RPC; `offenders.last_seen` bumped only |
| Active ban expires (`ExpireBans`) | Next hit records strike #2 (1-hour ban) |
| IP reaches permanent ban (strike #5, TTL=0) | Suppressed forever — permanent rows are never swept by `ExpireBans` |
| Daemon restart | Suppression resumes from `bans_active` (persisted in SQLite); no in-memory state required |

## Action `Op` values

| `Op` value | Meaning |
|---|---|
| `"ban"` | Strike recorded; enforcer RPC issued; ban active |
| `"dry_ban"` | Would ban; `armed=false`; no writes |
| `"already_banned"` | Suppressed: IP already in `bans_active`; only `last_seen` bumped |
| `"notify_only"` | Score in observe band; no ban |
| `"record"` | Below observe threshold, or allowlisted |

## Impact on `offenders.total_strikes`

Before this fix, `total_strikes` counted raw malicious requests (e.g. 60 for
a 66-second scanner burst at 1 req/s). With deduplication, `total_strikes`
counts distinct attack episodes — the number of times an IP came back and
attacked after a cooling-off period. This makes the field a meaningful
recidivism indicator.

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

**Real-world example** (Issue #48): An attacker targeting WordPress with 30 login attempts across 6 hours in 2–3 hit bursts. Each burst falls below the burst-tier threshold (3 hits/min) but accumulates 10+ hits in 1 hour, triggering sustained detection.

**Examples**:
- WordPress: 10+ `/wp-login` hits spread across 1 hour
- XML-RPC abuse: 8+ `/xmlrpc.php` probes across 1 hour
- HTTP scanning: 60+ distinct 404s across 1 hour
- SSH: 15+ failed logins across 1 hour

**Tuning**: Thresholds are set conservatively to avoid legitimate user activity:
- An admin who logs into WordPress 3–4 times per hour will not trigger
- An automated backup script making periodic requests will not trigger
- Legitimate crawlers hitting 404 occasionally will not trigger

### How They Work Together

1. **Burst rule fires first**: Catches aggressive probers immediately
2. **Sustained rule fires later**: Catches patient attackers that slip through
3. **Deduplication prevents double-banning**: Once an IP is in `bans_active`, sustained hits are suppressed (see Active-Ban Deduplication above)

### Adjusting Thresholds

To customize thresholds, edit `configs/rules.yaml` and adjust the `window` and `threshold` fields:

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

**Detected paths**: `phpunit`, `.git`, `.aws`, `cgi-bin`, actuator endpoints, `.env` variants, WordPress plugin shells, Terraform state, database configs, etc.

**Why threshold=1**: These paths have zero legitimate use in production. A single request to `/.git/config` or `/admin.php` is always suspicious.

**Why score=95**: Placed above the ambiguous band (0–90), so the decision engine never consults AI — rules verdict is final.

**No double-ban risk**: Exploit probes trigger instantly with score=95, so they enter `bans_active` before any burst-tier rule. Subsequent hits are suppressed by deduplication.

### Related exploit detection

Other rules targeting low-frequency errors that may indicate scanning:
- `http_scanner_400`: 10+ malformed requests (threshold=10, score=60)
- `http_scanner_503`: 15+ service unavailable responses (threshold=15, score=65)

These operate on the burst tier and allow more requests before triggering, since occasional 400/503 is legitimate.

## Related

- Issue #28: implementation and live evidence from kylian-s (2026-07-03/04)
- Issue #47: contains_any support and exploit probe detection (2026-07-08)
- Issue #48: sustained-tier rules for low & slow detection (2026-07-08)
- `internal/decision/engine.go`: `Engine.Decide` — active-ban guard
- `internal/store/store.go`: `HasActiveBan`, `BumpLastSeen`
- `docs/QUICKSTART.md`: strike table and deduplication semantics (PT-BR)
