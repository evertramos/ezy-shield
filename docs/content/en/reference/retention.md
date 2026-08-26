---
title: Data Retention
description: Configurable retention windows and safe database pruning
order: 7
---

# Data Retention

EzyShield's SQLite database grows without bound on attacked hosts: every strike, audit entry, and AI call adds a row. Retention pruning keeps the database bounded — and gives you a written retention policy for the personal data it holds (IP addresses are personal data under GDPR/LGPD; auditors ask how long you keep them).

Retention is **opt-in**: without a `retention:` section in `config.yaml`, nothing is ever pruned.

## Configuration

```yaml
retention:
  strikes: 730d      # strike history        (default 730d, floor 180d)
  audit: 365d        # audit journal         (default 365d, floor 90d)
  ai_usage: 90d      # AI cost accounting    (default 90d,  floor 7d)
  # i_understand_the_risks: true       # allow windows below the floors (never below 24h)
  # audit_export_not_required: true    # REQUIRED before audit_log rows are ever deleted
```

Durations accept Go syntax plus a day unit (`30d`, `365d`, `2160h`). The literal `never` (or `0`) disables pruning for that table. Values below the per-table floors are rejected unless `i_understand_the_risks: true` — and even then a 24h absolute minimum applies.

## What gets pruned — and what never is

| Table | Window | Semantics |
|---|---|---|
| `strikes` | `strikes` | Rows older than the window. The **most recent strike of any IP with an active ban is never deleted**, whatever its age. |
| `offenders` | `strikes` | Only IPs whose *entire* strike history has aged out **and** that have no active ban. |
| `audit_log` | `audit` | Rows older than the window — **only** with `audit_export_not_required: true` (see below). |
| `ai_usage` | `ai_usage` | Rows older than the window. |
| `bans_active` | — | **Never touched.** Active bans are enforcement state, not history. |
| `allowlist` | — | **Never touched.** |

**The strikes trade-off.** Strike history powers repeat-offender escalation. The escalation counter (`total_strikes`) is *not* decremented when old strike rows are pruned — a repeat offender keeps escalating. But once an IP's entire history ages out (no strike inside the window, no active ban), its offender row is dropped and escalation restarts from strike 1 the next time it attacks. That's why the `strikes` floor is 180 days and the default two years.

**The audit gate.** `audit_log` is EzyShield's append-only security journal; deletion is the exception, not the rule. Until an export mechanism records what has been archived (SIEM forwarding is the planned archival path), audit pruning refuses to run unless you explicitly set `audit_export_not_required: true` — acknowledging rows will be deleted without any copy existing elsewhere. Every prune run writes its own `retention_prune` summary rows (table, rows deleted, window) *into* the audit log, so the deletion itself stays traceable.

## When it runs

The daemon runs the prune once per day (first run delayed and jittered so a fleet doesn't vacuum in lockstep). Deletes are batched (500 rows per transaction, yielding between batches) so a large backlog never blocks detection. After pruning, the database file is compacted (`VACUUM`) only when free space exceeds 25% of the file.

## Manual runs

```console
# Preview: per-table candidate counts, deletes nothing
$ ezyshield maintenance prune --dry-run

# Real run: requires explicit confirmation
$ ezyshield maintenance prune --yes
```

Both go through the daemon's control socket, so file permissions and the audit trail are identical to the daily job.
