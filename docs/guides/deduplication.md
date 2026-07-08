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

## Related

- Issue #28: implementation and live evidence from kylian-s (2026-07-03/04)
- `internal/decision/engine.go`: `Engine.Decide` — active-ban guard
- `internal/store/store.go`: `HasActiveBan`, `BumpLastSeen`
- `docs/QUICKSTART.md`: strike table and deduplication semantics (PT-BR)
