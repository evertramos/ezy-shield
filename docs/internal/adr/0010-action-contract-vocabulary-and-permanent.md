# ADR-0010 — Action contract: closed Op vocabulary and the Permanent field

- Status: accepted
- Date: 2026-08-25
- Issues: #315 (contract drift), #279 (Permanent's origin), #211/#146/ADR-0009 (op producers)

## Context

`sdk.Action` is a §3 contract (ARCHITECTURE.md): changing it requires an
ADR. Two changes happened without one, and the documentation drifted from
the code in both directions (issue #315):

1. The documented `Op` list — `"ban", "unban", "ratelimit", "notify_only"`
   — no longer matched reality. The engine and daemon emit `record`,
   `dry_ban` (ADR-0009 §5), `already_banned` (issues #28/#29),
   `expired`, and `allow_add`; nothing has ever emitted `ratelimit`
   (rate-limit breaches surface as `decision.ErrRateLimited`, not as an
   Action).
2. `Permanent bool` was added for issue #279 (a remaining-TTL that reached
   zero must never be conflated with "no expiry at all") with no ADR — and
   the engine itself never set it: the permanent strike rung emitted
   `TTL: 0` with `Permanent` unset, the exact conflation the field's own
   doc forbids. SDK consumers following the documented contract would
   misclassify engine-produced permanent bans.

## Decision

1. **The Op vocabulary is closed and is exactly:**

   | Op | Meaning | Producer |
   |----|---------|----------|
   | `ban` | enforceable ban (armed) | engine, manual ban |
   | `dry_ban` | simulated ban — recorded, never enforced (ADR-0009 §5) | engine, manual ban |
   | `unban` | ban lifted | manual unban |
   | `expired` | ban TTL elapsed and was removed | expiry loop |
   | `record` | observed below the notify band, or an anti-lockout refusal (`Reason` distinguishes — `decision.ReasonAntiLockoutSSHPeer` is a pinned contract) | engine |
   | `notify_only` | notify band — alert, no ban | engine |
   | `already_banned` | suppressed — the IP already has an active ban | engine |
   | `allow_add` | allowlist entry added | allow verb |

   `ratelimit` is removed from the documented list: a breached ban-rate cap
   is an error (`ErrRateLimited`), deliberately not an Action — actions are
   things that happened to an IP, and a paused pipeline is not one.
   Extending this vocabulary requires a new ADR.

2. **`Permanent` is ratified** (retroactively for #279) with these
   invariants:
   - `Permanent == true` ⇒ `TTL == 0`; the pair means "no expiry".
   - `TTL == 0` without `Permanent` is INVALID on ban-producing ops —
     producers must set `Permanent` explicitly. The engine's permanent
     strike rung now does (`internal/decision/engine.go`, ban action
     build), pinned by `TestDecide_PermanentRungSetsPermanent`.
   - Consumers (notifiers, SIEM export, plugins) must key "is this ban
     permanent?" on `Permanent`, never on `TTL == 0`.

## Consequences

- ARCHITECTURE.md §3's `Action` struct is updated to carry `Permanent` and
  the full vocabulary (same wording as `pkg/sdk/types.go`, which remains
  the normative copy).
- Existing consumers that treated `TTL == 0` as permanent keep working
  (the invariant makes the two agree); consumers that trusted the old
  four-value list gain five documented values they may previously have
  dropped on the floor.
- Any future Op value or Action field lands with an ADR referencing this
  one.
