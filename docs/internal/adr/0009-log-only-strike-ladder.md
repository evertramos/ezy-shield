# ADR-0009: Log-only strike ladder — suppression, re-offense escalation, ban_ineffective

**Status:** Accepted
**Date:** 2026-07-13

## Context

Two production incidents exposed the strike ladder's semantics as underspecified
(issue #29):

1. One log burst advanced an IP from strike 1 to strike 5 (permanent) in 5.2
   seconds — the ladder consumed all rungs inside a single episode. Issue #28
   fixed the mechanism (active-ban guard: re-hits during an active ban are
   suppressed), but the semantics were never recorded.
2. A banned IP kept producing fresh log lines throughout its ban. Root cause:
   a CDN in front of the server — the client IP never reaches nftables, so the
   local L3 ban blocks nothing.

The open design questions were: what does activity during a ban *mean*, when
does the ladder escalate, and how is attacker persistence detected? An earlier
draft proposed nftables per-element counters to measure persistence (dropped
packets during the ban → escalate at expiry).

The key observation: in a healthy armed setup, a banned IP **cannot** produce
new log lines — packets die at the firewall before reaching any service. A log
line mentioning a banned IP is therefore always an *enforcement anomaly*
signal (CDN/proxy in front, conntrack not flushed, enforcer bug, v4/v6
mismatch), never a persistence signal.

## Decision

The ladder is **log-only**. Semantics, in order of evaluation:

1. **One episode → one strike.** The #28 active-ban guard is the foundation:
   a detection burst produces strike *k* and one ban with the ladder's TTL for
   rung *k* (`policy.strikes`, cumulative `total_strikes` indexes the table,
   clamped at the last entry = permanent).
2. **During an active ban: no new strikes, ever.** Events mentioning the
   banned IP are suppressed from sentencing but **counted** per ban.
3. **Ladder = re-offense.** A new episode after the ban expires takes the next
   rung. Escalation bans are exempt from `max_bans_per_minute`: they extend an
   existing block for a known offender and add zero new-lockout risk; they are
   still fully audited.
4. **`ban_ineffective` diagnostic** (armed-only): fires when ≥ `min_events`
   suppressed events occur ≥ `grace_seconds` after the ban was applied.
   Defaults `min_events = 3`, `grace_seconds = 90` are **floors** — policy may
   raise them, never lower them (below that, in-flight requests, proxy
   buffering, and log-write latency false-alarm on effective bans). The signal
   is **purely diagnostic: it never escalates nor holds the ladder.** It emits
   a structured WARN + stream event + notification carrying ladder context
   ("strike 3/5 — next rungs: 7d, permanent"), plus a `doctor` check. A
   distinct, louder event fires when the ladder promotes to permanent an IP
   that had `ban_ineffective` during a previous ban — an ineffective permanent
   ban is the one case that must never pass silently.
5. **Dry-run mirrors armed.** A dry-ban records its strike and suppresses new
   strikes during its simulated TTL, so dry-run shows exactly the escalation
   production would apply. `ban_ineffective` stays armed-only: in dry-run,
   traffic during a "ban" is expected, not an anomaly.
6. **Decay** (implementation deferred to v0.2): the *effective* ladder
   position regresses one rung per clean period (default 30 days,
   policy-configurable); permanent never auto-regresses. Decay affects
   **sentencing, not memory**: `offenders.first_seen`, `total_strikes`, strike
   rows and the append-only `audit_log` are never rewritten.
7. The AI path never short-circuits the ladder: AI verdicts suggest TTLs,
   policy clamps them, the ladder advances one rung at a time (existing
   invariant).

### Rejected: nftables per-element counters

Persistence-at-expiry detection via kernel counters is rejected for this
iteration. Cost: a new read verb across the enforcer privilege boundary (🔴),
`nft -j` output parsing across nft/kernel versions, a subtle bug class
(reconcile must never recreate an existing set element — recreation silently
zeroes its counter), and conntrack flushing as a correctness prerequisite.
Benefit: counters observe only the *local* nftables path — blind behind a CDN
(the incident that motivated this issue) and for edge bans, which have no
counters at all. Over the re-offense ladder they add only "escalate at expiry
instead of on the first post-expiry re-offense". For one-shot scanners that
never return, *any* ladder is decorative — including a counter-based one. If
real deployments show the re-offense ladder escalating too slowly against
sustained attackers, the revisit gets its own issue.

## Consequences

- The 1→5-in-seconds runaway is structurally impossible: rung advances require
  a ban to expire first.
- The ladder is meaningful exactly for the actors it exists for — returners.
- `ban_ineffective` cannot be forged in the harmful direction: it derives from
  log events, which only exist if traffic actually got through the ban.
- The signal is systemic (broken enforcement fires it for many IPs at once):
  notifications must be deduplicated; the remedy it points to is edge
  enforcement / real-IP parsing or enforcer repair, never per-IP sentencing.
- Dry-run semantics change: `dry_ban` now records strikes and suppresses like
  a real ban (previously it recorded nothing) — user docs must state this.
- No new privilege-boundary surface in the enforcer.
- Behind a CDN, local bans remain ineffective by construction; the diagnostic
  makes that visible instead of pretending the ban worked.
