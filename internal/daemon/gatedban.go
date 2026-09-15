// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// gatedban.go — deferred enforcement after the enforce-side gate refuses a
// ban the store already holds (issue #583).
//
// Decide commits the bans_active row BEFORE dispatch reaches the enforcer,
// and the decision engine's SSH-peer check reads a TTL-cached peer list
// while the gate (internal/enforce/gate.go) probes fresh. A fast-reconnect
// bruteforcer lands in that gap routinely: the engine bans, the gate
// refuses ("active SSH peer"). Until this file the daemon treated that
// like a broken enforcer — ERROR plus a critical notification — and then
// forgot about it: the row sat in the store (every later event from the IP
// already_banned-suppressed, so no re-decision and no #420 re-check, which
// only arms on op=record) until some reconcile happened to run. On a quiet
// host that is never; on the dogfood host it was 3–5 minutes per ban and,
// once, a whole 24 h strike-3 ban (audit 2026-09-08).
//
// Fix: a gate refusal of a stored ban arms ONE deferred enforcement retry
// per IP on the #420 cadence (delay ≥ 2× the peer-cache TTL, bounded by
// sshRecheckMaxAttempts). Each retry re-reads the store — a ban that
// expired or was lifted meanwhile is dropped, never re-applied — and calls
// the enforcer again with the REMAINING TTL, through the same gate. The
// anti-lockout invariant (Hard Rule 1) is untouched: an allowlisted target
// or an operator's live session is refused on every attempt and never
// enforced; the retry can only apply what the gate no longer refuses.
// Exhaustion is loud (WARN) and audited (op "enforce_deferred_exhausted");
// the periodic reconcile stays the backstop for what the budget did not
// cover.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// deferGatedBan arms the deferred enforcement retry for ip after the gate
// refused its ban at dispatch time. cause is the gate's error (logged, so
// the refusal reason travels with the WARN).
func (d *Daemon) deferGatedBan(ctx context.Context, ip netip.Addr, cause error) {
	delay := d.sshRecheckDelayVal()
	slog.WarnContext(ctx, "daemon: enforcement gate refused a stored ban — deferring enforcement",
		"ip", ip, "retry_in", delay, "err", cause)
	if !d.gatedBanRetry.schedule(ip, d.clock().Add(delay), nil) {
		slog.WarnContext(ctx, "daemon: deferred-enforcement queue full — retry dropped, the reconcile will apply the ban",
			"ip", ip)
	}
}

// retryGatedBan is one deferred attempt: re-read the stored ban, re-apply
// it through the gate with the remaining TTL, re-arm on a fresh refusal.
// attempts on the item is the budget already spent.
func (d *Daemon) retryGatedBan(ctx context.Context, it sshRecheckItem) {
	ip, attempts := it.ip, it.attempts+1
	if ctx.Err() != nil {
		return
	}

	// Store read + kernel write under enforceMu (issue #575), exactly like
	// dispatch: a reconcile cannot snapshot the store between the two and
	// classify the fresh entry as stale.
	d.enforceMu.Lock()
	target, active, err := d.storedBanTarget(ctx, ip)
	if err != nil {
		d.enforceMu.Unlock()
		slog.ErrorContext(ctx, "daemon: deferred enforcement — cannot read stored ban", "ip", ip, "err", err)
		return
	}
	if !active {
		d.enforceMu.Unlock()
		// Expired, lifted by the operator, or replaced by a dry-run row:
		// nothing to enforce, and re-applying it would be a ban the store
		// no longer justifies.
		slog.DebugContext(ctx, "daemon: deferred enforcement — ban no longer active, dropping", "ip", ip)
		return
	}
	err = d.enforcer.Ban(ctx, target)
	d.enforceMu.Unlock()

	switch {
	case err == nil:
		slog.InfoContext(ctx, "daemon: deferred enforcement applied after gate refusal",
			"ip", ip, "attempt", attempts, "ttl", target.TTL)
		d.recordEnforceResult(ctx, "ban", nil)
		if d.metrics != nil {
			d.metrics.bansApplied.With(d.enforcer.Name()).Inc()
		}
	case errors.Is(err, enforce.ErrGateRefused):
		// Still guarded (peer still present, or the target became
		// allowlisted): the invariant held. Re-arm within the budget.
		if !d.gatedBanRetry.requeue(ip, attempts, d.clock().Add(d.sshRecheckDelayVal()), nil) {
			d.noteGatedBanExhausted(ctx, ip, attempts)
		}
	default:
		// A real enforcer failure on the retry path gets the same
		// treatment the dispatch path gives it: loud, and DEGRADED.
		slog.ErrorContext(ctx, "daemon: deferred enforcement failed", "ip", ip, "attempt", attempts, "err", err)
		d.notifyEnforcerFailure(ctx, ip, err)
		d.recordEnforceResult(ctx, "ban", err)
	}
}

// storedBanTarget returns the enforcer target for ip's active, real (not
// dry-run) ban with its remaining TTL, and active=false when the store no
// longer holds one. It reads the same view the reconcile enforces from
// (ActiveBans), so the two paths can never disagree on what is active.
func (d *Daemon) storedBanTarget(ctx context.Context, ip netip.Addr) (sdk.Target, bool, error) {
	bans, err := d.store.ActiveBans(ctx)
	if err != nil {
		return sdk.Target{}, false, fmt.Errorf("load active bans: %w", err)
	}
	want := ip.Unmap()
	for _, b := range bans {
		if b.Op == "ban" && b.IP.Unmap() == want {
			return sdk.Target{IP: b.IP, TTL: b.TTL}, true, nil
		}
	}
	return sdk.Target{}, false, nil
}

// noteGatedBanExhausted makes an exhausted retry budget loud and queryable,
// mirroring noteSSHRecheckDropped (issue #559): the ban is still in the
// store and still unenforced, and only the next reconcile will apply it —
// an operator auditing "banned but traffic flowed" must be able to find
// why. Bare-IP audit row so `report <ip>` renders it.
func (d *Daemon) noteGatedBanExhausted(ctx context.Context, ip netip.Addr, attempts int) {
	slog.WarnContext(ctx, "daemon: deferred enforcement retry budget exhausted — ban stays in the store until the next reconcile",
		"ip", ip, "attempts", attempts)
	reason := fmt.Sprintf(
		"enforcement gate refused the stored ban on all %d deferred attempts (peer still guarded) — entry left to the next reconcile", attempts)
	if err := d.store.Audit(ctx, sdk.Action{IP: ip.Unmap(), Op: "enforce_deferred_exhausted", Reason: reason}); err != nil {
		slog.ErrorContext(ctx, "daemon: audit enforce_deferred_exhausted failed", "ip", ip, "err", err)
	}
}
