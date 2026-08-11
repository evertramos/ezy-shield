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
// (Result 5 of the same audit) without changing the outcome.

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
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
}

type sshRecheckEntry struct {
	due      time.Time
	attempts int
}

// sshRecheckQueue is the per-IP deferred re-check schedule. All methods are
// safe for concurrent use (pipeline goroutine schedules, re-check goroutine
// pops and re-arms).
type sshRecheckQueue struct {
	mu      sync.Mutex
	pending map[netip.Addr]*sshRecheckEntry
}

// schedule (re)arms the re-check for ip after an event-driven refusal:
// deadline pushed to due, attempts reset (fresh evidence, fresh budget).
// Returns false when the queue is full and ip is not already tracked.
func (q *sshRecheckQueue) schedule(ip netip.Addr, due time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e, ok := q.pending[ip]; ok {
		e.due = due
		e.attempts = 0
		return true
	}
	if len(q.pending) >= sshRecheckMaxPending {
		return false
	}
	if q.pending == nil {
		q.pending = make(map[netip.Addr]*sshRecheckEntry)
	}
	q.pending[ip] = &sshRecheckEntry{due: due}
	return true
}

// requeue re-arms after a re-check that was itself refused (peer still
// ESTABLISHED) or rate-limited. attempts is the count ALREADY spent; returns
// false when the retry budget is exhausted. If a fresh event-driven refusal
// re-armed ip meanwhile, that entry (newer deadline, reset budget) wins.
func (q *sshRecheckQueue) requeue(ip netip.Addr, attempts int, due time.Time) bool {
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
	q.pending[ip] = &sshRecheckEntry{due: due, attempts: attempts}
	return true
}

// due pops and returns every entry whose deadline has passed.
func (q *sshRecheckQueue) due(now time.Time) []sshRecheckItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	var items []sshRecheckItem
	for ip, e := range q.pending {
		if !e.due.After(now) {
			items = append(items, sshRecheckItem{ip: ip, attempts: e.attempts})
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
	if !d.sshRecheck.schedule(action.IP, time.Now().Add(d.sshRecheckDelayVal())) {
		slog.WarnContext(ctx, "daemon: ssh re-check queue full — deferred re-evaluation dropped",
			"ip", action.IP)
	}
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
				d.recheckAfterAntiLockout(ctx, it.ip, it.attempts)
			}
		}
	}
}

// recheckAfterAntiLockout re-runs the pipeline tail for ip from live state.
// Every protection re-applies on this pass: runtime allowlist here, then
// static allowlist, SSH-peer probe (fresh — the delay outlives the cache
// TTL), active-ban guard, and the ban rate limit inside Decide. attempts is
// the retry budget already spent for this evidence.
func (d *Daemon) recheckAfterAntiLockout(ctx context.Context, ip netip.Addr, attempts int) {
	if ctx.Err() != nil {
		return
	}
	if d.isRuntimeAllowlisted(ip) {
		slog.DebugContext(ctx, "daemon: ssh re-check — runtime-allowlisted, dropping", "ip", ip)
		return
	}

	verdicts := d.evaluateRules(ctx, ip)
	verdicts = d.maybeInjectGeoVerdict(ctx, ip, verdicts)
	if len(verdicts) == 0 {
		// The evidence aged out of every rule window — nothing left to decide.
		slog.DebugContext(ctx, "daemon: ssh re-check — no in-window verdicts, dropping", "ip", ip)
		return
	}

	action, err := d.decEng.Decide(ctx, verdicts)
	if err != nil {
		if errors.Is(err, decision.ErrRateLimited) {
			// Cap honored (Hard Rule 1): alert like the pipeline path does and
			// retry later, bounded by the attempt budget.
			slog.WarnContext(ctx, "daemon: ssh re-check hit ban rate limit — deferring", "ip", ip)
			d.notifyCritical(ctx, "ban rate limit exceeded")
			d.sshRecheck.requeue(ip, attempts+1, time.Now().Add(d.sshRecheckDelayVal()))
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
		// connection. The invariant held; re-arm within the retry budget.
		d.sshRecheck.requeue(ip, attempts+1, time.Now().Add(d.sshRecheckDelayVal()))
	}
}
