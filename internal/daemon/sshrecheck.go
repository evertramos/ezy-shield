// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// sshrecheck.go — deferred re-evaluation after an SSH-peer anti-lockout
// refusal (issue #420).
//
// The decision engine refuses to ban any IP the kernel reports as an
// ESTABLISHED SSH peer (internal/decision/sshpeers.go, issue #175). That
// invariant is correct and untouched here — but it interacts badly with a
// fast-reconnect bruteforcer: each failed attempt is a fresh short-lived
// connection, reconnecting faster than the peer-cache TTL, so EVERY
// evaluation in the threshold window happens to see an ESTABLISHED peer and
// is refused. When the burst ends the attacker goes quiet, and since the
// pipeline only evaluates on incoming events, the still-in-window evidence
// is never looked at again — zero strikes, zero ban (kylian audit
// 2026-08-06, Result 2).
//
// Fix: when a refusal suppressed a would-be ban (highest verdict score ≥
// ban_threshold), the daemon arms ONE deferred re-evaluation per IP, firing
// ≥ 2× the peer-cache TTL after the LAST refusal (each new refusal pushes it
// back). The re-check re-runs the normal pipeline tail from LIVE state —
// runtime allowlist, rule engine over the current aggregates, then the full
// decision path (static allowlist, fresh kernel SSH-peer probe, active-ban
// guard, max-bans-per-minute) — never from stored verdicts, so no safety
// check is skipped and nothing stale can ban. If the peer is STILL
// established (a genuine operator session, or an attacker holding the
// connection), the refusal simply repeats and the re-check re-arms, bounded
// by sshRecheckMaxAttempts. The anti-lockout invariant is therefore intact:
// a ban can only ever result from a full Decide pass that found no
// ESTABLISHED connection at that moment.
//
// The AI layer is deliberately NOT consulted on re-checks: the evidence
// already went through maybeConsultAI when the events arrived, and rule/geo
// scores are deterministic — re-asking would only double-spend budget
// (Result 5 of the same audit) without changing the outcome. Instead, when
// the ORIGINAL refusal suppressed a ban that needed the AI push (rules-only
// score below ban_threshold, an ai:* verdict at/above it — issue #442), the
// elevated verdict is carried on the queue entry and REPLAYED into the
// deferred Decide alongside the freshly derived rule/geo verdicts. Replay
// happens only while in-window rule evidence still exists (aged-out
// evidence still drops), the verdict's IP is re-checked against the entry
// (same discipline as the #402 rebind), and every safety check in Decide —
// fresh SSH-peer probe included — applies to the replayed verdict exactly
// as it did originally.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	// defaultSSHRecheckDelay is how long after the LAST anti-lockout refusal
	// the deferred re-evaluation fires. ≥ 2× the peer-cache TTL guarantees
	// the re-check consults a fresh /proc probe, never the cached peer list
	// that justified the refusal.
	defaultSSHRecheckDelay = 2 * decision.SSHPeerCacheTTL
	// defaultSSHRecheckTick is how often due re-checks are looked for.
	defaultSSHRecheckTick = time.Second
	// sshRecheckMaxAttempts bounds re-arms when the peer stays ESTABLISHED
	// at every re-check (operator session, or attacker holding the
	// connection open). 15 × 4s ≈ one 60s rule window of quiet-period
	// retries; past that, only a fresh event-driven refusal re-arms —
	// exactly what a still-active attacker generates anyway.
	sshRecheckMaxAttempts = 15
	// sshRecheckMaxPending caps the queue. Overflow drops the NEW entry,
	// degrading to pre-#420 behavior (no re-check) — the safe direction.
	// Entries require real ESTABLISHED sshd connections, so the cap is
	// unreachable without the attacker first surviving the rule engine
	// 1024 times in one delay window.
	sshRecheckMaxPending = 1024
)

// sshRecheckItem is a due re-check popped from the queue.
type sshRecheckItem struct {
	ip       netip.Addr
	attempts int
	// aiVerdict is the AI-elevated verdict that made the original refusal a
	// would-be ban when rules alone did not reach ban_threshold; nil when
	// rules alone sufficed (issue #442). Replayed into the deferred Decide.
	aiVerdict *sdk.Verdict
}

type sshRecheckEntry struct {
	due       time.Time
	attempts  int
	aiVerdict *sdk.Verdict // see sshRecheckItem.aiVerdict
}

// sshRecheckQueue is the per-IP deferred re-check schedule. All methods are
// safe for concurrent use (pipeline goroutine schedules, re-check goroutine
// pops and re-arms).
type sshRecheckQueue struct {
	mu      sync.Mutex
	pending map[netip.Addr]*sshRecheckEntry
}

// schedule (re)arms the re-check for ip after an event-driven refusal:
// deadline pushed to due, attempts reset (fresh evidence, fresh budget),
// aiVerdict replaced (the newest refusal's evidence wins — nil when rules
// alone reached ban_threshold, issue #442). Returns false when the queue is
// full and ip is not already tracked.
func (q *sshRecheckQueue) schedule(ip netip.Addr, due time.Time, aiVerdict *sdk.Verdict) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e, ok := q.pending[ip]; ok {
		e.due = due
		e.attempts = 0
		e.aiVerdict = aiVerdict
		return true
	}
	if len(q.pending) >= sshRecheckMaxPending {
		return false
	}
	if q.pending == nil {
		q.pending = make(map[netip.Addr]*sshRecheckEntry)
	}
	q.pending[ip] = &sshRecheckEntry{due: due, aiVerdict: aiVerdict}
	return true
}

// requeue re-arms after a re-check that was itself refused (peer still
// ESTABLISHED) or rate-limited. attempts is the count ALREADY spent; returns
// false when the retry budget is exhausted. If a fresh event-driven refusal
// re-armed ip meanwhile, that entry (newer deadline, reset budget) wins.
func (q *sshRecheckQueue) requeue(ip netip.Addr, attempts int, due time.Time, aiVerdict *sdk.Verdict) bool {
	if attempts >= sshRecheckMaxAttempts {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.pending[ip]; ok {
		return true
	}
	if len(q.pending) >= sshRecheckMaxPending {
		return false
	}
	if q.pending == nil {
		q.pending = make(map[netip.Addr]*sshRecheckEntry)
	}
	q.pending[ip] = &sshRecheckEntry{due: due, attempts: attempts, aiVerdict: aiVerdict}
	return true
}

// due pops and returns every entry whose deadline has passed.
func (q *sshRecheckQueue) due(now time.Time) []sshRecheckItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	var items []sshRecheckItem
	for ip, e := range q.pending {
		if !e.due.After(now) {
			items = append(items, sshRecheckItem{ip: ip, attempts: e.attempts, aiVerdict: e.aiVerdict})
			delete(q.pending, ip)
		}
	}
	return items
}

// len reports the number of armed re-checks (tests / observability).
func (q *sshRecheckQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

// sshRecheckDelayVal returns the configured delay (tests) or the default.
func (d *Daemon) sshRecheckDelayVal() time.Duration {
	if d.sshRecheckDelay > 0 {
		return d.sshRecheckDelay
	}
	return defaultSSHRecheckDelay
}

// maybeScheduleSSHRecheck arms a deferred re-evaluation when action is an
// SSH-peer anti-lockout refusal that suppressed a would-be ban. Refusals of
// sub-threshold verdicts are not armed: re-checking them could never change
// the outcome (Decide would record either way).
func (d *Daemon) maybeScheduleSSHRecheck(ctx context.Context, action sdk.Action, verdicts []sdk.Verdict) {
	if action.Op != "record" || action.Reason != decision.ReasonAntiLockoutSSHPeer {
		return
	}
	high := 0
	for _, v := range verdicts {
		if v.Score > high {
			high = v.Score
		}
	}
	if high < d.policy.BanThreshold {
		return
	}
	if !d.sshRecheck.schedule(action.IP, time.Now().Add(d.sshRecheckDelayVal()),
		elevatedAIVerdict(verdicts, d.policy.BanThreshold)) {
		slog.WarnContext(ctx, "daemon: ssh re-check queue full — deferred re-evaluation dropped",
			"ip", action.IP)
	}
}

// elevatedAIVerdict returns (a copy of) the highest-scoring ai:* verdict at
// or above banThreshold — but only when the non-AI verdicts alone stay
// BELOW the threshold, i.e. the would-be ban existed only because of the AI
// push (issue #442). When rules alone suffice, nil: the deferred re-check
// reproduces the ban from live rule evidence and a replay would be
// redundant.
func elevatedAIVerdict(verdicts []sdk.Verdict, banThreshold int) *sdk.Verdict {
	nonAIHigh := 0
	var best *sdk.Verdict
	for i := range verdicts {
		v := &verdicts[i]
		if strings.HasPrefix(v.Source, "ai:") {
			if v.Score >= banThreshold && (best == nil || v.Score > best.Score) {
				best = v
			}
			continue
		}
		if v.Score > nonAIHigh {
			nonAIHigh = v.Score
		}
	}
	if best == nil || nonAIHigh >= banThreshold {
		return nil
	}
	cp := *best
	return &cp
}

// runSSHRecheck is the re-check loop goroutine: it pops due entries every
// tick and re-evaluates them. Exits when ctx is cancelled (no leak).
func (d *Daemon) runSSHRecheck(ctx context.Context) {
	tick := d.sshRecheckTick
	if tick <= 0 {
		tick = defaultSSHRecheckTick
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			for _, it := range d.sshRecheck.due(now) {
				d.recheckAfterAntiLockout(ctx, it)
			}
		}
	}
}

// recheckAfterAntiLockout re-runs the pipeline tail for ip from live state.
// Every protection re-applies on this pass: runtime allowlist here, then
// static allowlist, SSH-peer probe (fresh — the delay outlives the cache
// TTL), active-ban guard, and the ban rate limit inside Decide. attempts is
// the retry budget already spent for this evidence.
func (d *Daemon) recheckAfterAntiLockout(ctx context.Context, it sshRecheckItem) {
	ip, attempts := it.ip, it.attempts
	if ctx.Err() != nil {
		return
	}
	if d.isRuntimeAllowlisted(ip) {
		slog.DebugContext(ctx, "daemon: ssh re-check — runtime-allowlisted, dropping", "ip", ip)
		return
	}

	// withLong=true: this path is SSH-specific by construction, so the
	// long-window counters (issue #134) are part of the live evidence.
	verdicts := d.evaluateRules(ctx, ip, true)
	verdicts = d.maybeInjectGeoVerdict(ctx, ip, verdicts)
	if len(verdicts) == 0 {
		// The evidence aged out of every rule window — nothing left to
		// decide. A carried AI verdict is deliberately NOT replayed alone:
		// with no live rule evidence there is nothing for it to elevate.
		slog.DebugContext(ctx, "daemon: ssh re-check — no in-window verdicts, dropping", "ip", ip)
		return
	}
	// Replay the AI-elevated verdict that made the original refusal a
	// would-be ban (issue #442) — only alongside live rule evidence, and
	// only for the IP it was issued for (same rebind discipline as #402).
	// Every safety check in Decide, the fresh SSH-peer probe included,
	// applies to it exactly as on the original pass.
	if it.aiVerdict != nil {
		if it.aiVerdict.IP == ip {
			verdicts = append(verdicts, *it.aiVerdict)
		} else {
			slog.WarnContext(ctx, "daemon: ssh re-check — dropping carried AI verdict for mismatched IP",
				"entry_ip", ip, "verdict_ip", it.aiVerdict.IP)
		}
	}

	action, err := d.decEng.Decide(ctx, verdicts)
	if err != nil {
		if errors.Is(err, decision.ErrRateLimited) {
			// Cap honored (Hard Rule 1): alert like the pipeline path does and
			// retry later, bounded by the attempt budget.
			slog.WarnContext(ctx, "daemon: ssh re-check hit ban rate limit — deferring", "ip", ip)
			d.notifyCritical(ctx, "ban rate limit exceeded")
			if !d.sshRecheck.requeue(ip, attempts+1, time.Now().Add(d.sshRecheckDelayVal()), it.aiVerdict) {
				d.noteSSHRecheckDropped(ctx, ip, attempts+1)
			}
			return
		}
		slog.ErrorContext(ctx, "daemon: ssh re-check decide error", "ip", ip, "err", err)
		return
	}

	slog.InfoContext(ctx, "daemon: ssh re-check after anti-lockout refusal",
		"ip", ip, "op", action.Op, "attempt", attempts+1)
	d.dispatch(ctx, action)

	if action.Op == "record" && action.Reason == decision.ReasonAntiLockoutSSHPeer {
		// Still ESTABLISHED — an operator session or an attacker holding the
		// connection. The invariant held; re-arm within the retry budget,
		// keeping the carried verdict for the next pass.
		if !d.sshRecheck.requeue(ip, attempts+1, time.Now().Add(d.sshRecheckDelayVal()), it.aiVerdict) {
			d.noteSSHRecheckDropped(ctx, ip, attempts+1)
		}
	}
}

// noteSSHRecheckDropped makes a dropped deferred re-evaluation LOUD and
// QUERYABLE (issue #559). A peer that simply holds the SSH socket in
// ESTABLISHED (sshd's "Timeout before authentication" pattern) outlasts the
// retry budget; before this, the evidence vanished with no WARN, no
// offender row, and `report <ip>` answering "no records". Now:
//
//   - a WARN mirrors the queue-full message from the initial-schedule path
//     (parity — this was the only silent drop in the file);
//   - an append-only audit entry (op "recheck_exhausted") records that a
//     would-be ban was suppressed, so ban-audits can find it;
//   - the offenders row is upserted (0 strikes), which is exactly the gate
//     `report` checks — the IP's full audit trail (the refusals were
//     already audited) becomes visible to `ezyshield report <ip>`.
//
// Observability only: no strike, no ban, no enforcement — the anti-lockout
// invariant (Hard Rule 1) is untouched. The budget resets on any fresh
// event-driven refusal (schedule zeroes attempts), so a peer that emits new
// parseable evidence re-arms the re-check as before. The authenticated-vs-
// unauthenticated peer distinction is tier 2 (follow-up issue).
func (d *Daemon) noteSSHRecheckDropped(ctx context.Context, ip netip.Addr, attempts int) {
	slog.WarnContext(ctx, "daemon: ssh re-check retry budget exhausted — deferred re-evaluation dropped",
		"ip", ip, "attempts", attempts)

	reason := fmt.Sprintf(
		"ssh anti-lockout re-check retry budget exhausted after %d attempts — would-be ban evidence dropped while the peer held an ESTABLISHED SSH connection", attempts)
	// Audit (bare-IP row) rather than AuditOp (prefix row): AuditLogForIP —
	// what `report <ip>` renders — matches bare-IP rows only.
	if err := d.store.Audit(ctx, sdk.Action{IP: ip.Unmap(), Op: "recheck_exhausted", Reason: reason}); err != nil {
		slog.ErrorContext(ctx, "daemon: audit recheck_exhausted failed", "ip", ip, "err", err)
	}
	// The offenders row is the visibility gate buildAbuseReport checks:
	// with it, `report <ip>` surfaces the already-audited refusals instead
	// of "no records".
	if err := d.store.BumpLastSeen(ctx, ip.Unmap()); err != nil {
		slog.ErrorContext(ctx, "daemon: offender upsert after re-check exhaustion failed", "ip", ip, "err", err)
	}
}
