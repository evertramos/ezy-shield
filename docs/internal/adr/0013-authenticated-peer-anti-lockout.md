# ADR-0013: Anti-lockout immunity requires an authenticated peer (logind-verified, fail-open)

Date: 2026-08-26
Status: Proposed (decision owner: maintainer — Hard Rule 1 territory)
Issue: #560 (tier 2 of #559; refs #384, #420, #175)

## Context

The SSH anti-lockout grants ban immunity to any IP the kernel reports as
an `ESTABLISHED` peer on the sshd port(s) (`/proc/net/tcp`, 2s cache,
checked in the decision engine and again at the enforcement gate; #175).
The kernel answers "is there a TCP connection?" — it cannot answer "did
anyone log in on it?". A connection parked in sshd's `Timeout before
authentication` looks identical to an operator session, so an attacker
who holds sockets open buys continuous immunity (exploited live on the
kylian dogfood host — #559). Tier 1 made that exhaustion loud and
queryable; this ADR closes the underlying gap.

The design goal is explicitly two-sided: **more** safety for the admin
(and their automation), **less** free immunity for the attacker.

### Who must stay protected (the session matrix)

| Truth source | Interactive admin login | Non-interactive automation (`ssh host 'cmd'` — Claude/Kiro agents) | Attacker holding an unauthenticated socket |
|---|---|---|---|
| `/proc/net/tcp` (status quo) | immune ✅ | immune ✅ | immune ❌ **(the bug)** |
| `utmp` (`who`/`w`) | immune ✅ | **not immune** ❌ (no PTY → no utmp entry) | bannable ✅ |
| `loginctl` (systemd-logind) | immune ✅ | immune ✅ (PAM session opens with or without a TTY) | bannable ✅ |

The maintainer's own workflow drives actions through non-interactive SSH
(AI agents). Any option that drops automation from the safety net fails
the "safety for the admin" half of the goal — which rules out utmp as the
primary source.

## Options considered

**(a) Status quo — ESTABLISHED only.** Zero regression risk for
operators; leaves the #559 hole open (tier 1 only makes it visible).

**(b) utmp cross-check.** Simple, no systemd dependency, but silently
removes immunity from every non-interactive authenticated session (the
automation case above) and utmp is famously best-effort (stale/missing
entries). Rejected as primary source.

**(c) logind cross-check (proposed).** An `ESTABLISHED` peer is immune
only if systemd-logind also reports an **active session whose RemoteHost
is that IP** (`loginctl list-sessions` → `show-session -p RemoteHost -p
State`). logind sessions are opened by PAM for interactive *and*
non-interactive SSH, and close on logout — exactly the
"authenticated right now" signal we need. Requires systemd-logind.

**(d) Auth-failure veto (heuristic).** Deny immunity to a peer whose IP
has auth failures in the current evaluation window. Cheap, no logind
dependency — but it is inference, not proof: an admin fat-fingering a
password from a second terminal while their real session is open would
lose the veto's protection unless combined with (c). Kept only as an
optional belt-and-braces refinement, never the primary mechanism.

## Decision (proposed)

Adopt **(c) logind as the positive proof of an authenticated peer**, with
hard **fail-open** rules so no failure mode can ever tighten immunity by
accident:

1. **Immunity =** static allowlist/`admin_cidrs` (unchanged, checked
   first) **OR** (`ESTABLISHED` SSH peer **AND** active logind session
   with `RemoteHost` == that IP).
2. **Fail open, always toward the admin:** if logind is absent, errors,
   or times out (budget ~1s, cached ~5s like the peer probe), the check
   degrades to today's behavior — `ESTABLISHED` alone grants immunity. A
   logind hiccup must never enable a ban that today's code would refuse.
3. **Race window (login just completed):** a session may authenticate
   milliseconds before the probe reads logind. Before acting on
   "ESTABLISHED but no logind session", the ban path re-probes logind
   once after a short delay (~500ms). The #420 deferred re-check
   machinery additionally retries the whole decision; a real session
   appears on the next pass.
4. **Rollout is opt-in first:** config
   `anti_lockout.require_authenticated: true|false`, **default `false`
   in the first release** (current behavior), flipped to `true` only
   after a dogfood cycle on kylian confirms zero operator lockouts. The
   flag and its semantics are documented in the config reference; doctor
   reports which mode is active and whether logind is usable.
5. **Optional refinement (post-flip, separate decision):** the (d) veto —
   deny immunity when the same IP crosses the ban threshold in-window —
   may be layered on top for non-systemd hosts. Not part of this change.

### Accepted risks (documented, not hidden)

- **Idle `ControlPersist` masters:** a multiplexed master with no open
  channel has no logind session and would lose immunity while idle. An
  idle master carries no operator activity; active work always has a
  channel (= a logind session). Mitigation for fixed operator IPs
  remains `admin_cidrs`. Documented in the guide.
- **Non-logind hosts** (rare for the supported platforms) keep today's
  weaker behavior permanently — stated honestly in the docs; the (d)
  veto is the eventual path for them.

### Hard Rule 1 proof obligations (implementation gate)

The implementing PR must carry a test matrix proving, with fixture
logind/proc data, that immunity holds for: interactive session,
non-interactive exec session, session mid-login race (re-probe path),
logind absent, logind timeout — and that ONLY the held-unauthenticated
socket becomes bannable. The #420/#559 harness (always-ESTABLISHED peer)
is extended rather than duplicated. Any FAIL in this matrix blocks the
default flip in perpetuity.

## Consequences

- The kylian attack class (hold socket, never authenticate) loses its
  immunity on systemd hosts once the flag is on — while the operator's
  interactive shells AND their SSH-driven automation stay protected.
- New read-only dependency at decision time: two `loginctl` calls,
  cached; no new privileges (logind queries work unprivileged via D-Bus).
- The enforcement gate and decision engine keep their two-layer
  structure; only the peer-immunity predicate narrows.

## Follow-ups on acceptance

1. Implementation issue with the matrix above + config flag + doctor
   check ("logind reachable; authenticated-peer mode: on/off/fallback").
2. Dogfood window on kylian with the flag on and tier-1 observability
   (#559) watching for refusal/exhaustion anomalies.
3. Default flip issue, gated on the dogfood result.
