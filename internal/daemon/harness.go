// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// harness.go — exported seams for the integration harness (issue #605).
// Each one is the body of a production tick or entry point, exposed so a
// test in internal/e2e can drive the real pipeline deterministically on the
// injectable clock (Config.Now) instead of waiting on tickers. Nothing here
// bypasses a guard: the same functions run in production, on timers.

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// ProcessRaw runs the full pipeline for one raw line — exactly what a
// collector's delivery triggers.
func (d *Daemon) ProcessRaw(ctx context.Context, raw sdk.RawLine) { d.processRaw(ctx, raw) }

// Reconcile runs one store→enforcer reconcile: the boot sync, the
// enforcement probe and the post-expiry sync all call this.
func (d *Daemon) Reconcile(ctx context.Context) error { return d.syncEnforcer(ctx) }

// ReconcileAllowlist reloads the runtime allowlist from the store and pushes
// the effective allowlist (policy ∪ runtime) to the enforcer's @allowed
// mirror — the boot sequence.
func (d *Daemon) ReconcileAllowlist(ctx context.Context) error {
	if err := d.reloadAllowlist(ctx); err != nil {
		return err
	}
	return d.syncEnforcerAllowlist(ctx)
}

// ExpireOnce runs the reaper body once at the daemon clock: expired bans are
// removed from the store and, when any were, the enforcer is reconciled.
func (d *Daemon) ExpireOnce(ctx context.Context) (int, error) {
	n, err := d.store.ExpireBans(ctx, d.clock())
	if err != nil {
		return 0, err
	}
	if n > 0 {
		if err := d.syncEnforcer(ctx); err != nil {
			slog.ErrorContext(ctx, "daemon: post-expire sync failed", "err", err)
		}
	}
	return n, nil
}

// FlushOnce runs the aggregator flush tick body once at the daemon clock —
// what runFlush does every flushInterval.
func (d *Daemon) FlushOnce(ctx context.Context) { d.flushAggregates(ctx, d.clock()) }

// RunDeferredOnce pops and runs every SSH re-check (#420) and deferred
// enforcement retry (#583) that is due at the daemon clock — one tick of
// the re-check loop.
func (d *Daemon) RunDeferredOnce(ctx context.Context) {
	now := d.clock()
	for _, it := range d.sshRecheck.due(now) {
		d.recheckAfterAntiLockout(ctx, it)
	}
	for _, it := range d.gatedBanRetry.due(now) {
		d.retryGatedBan(ctx, it)
	}
}

// Allow runs the `allow` socket verb exactly as the CLI would (store row,
// runtime allowlist, @allowed mirror, and — issue #608 — lifting any ban
// the prefix covers). reason is free text; forDur == 0 means permanent.
func (d *Daemon) Allow(ctx context.Context, target, reason, forDur string) SocketResponse {
	return d.handleAllow(ctx, SocketRequest{Verb: "allow", IP: target, Reason: reason, For: forDur})
}

// SetSSHPeerProbe replaces the decision engine's SSH-peer probe (the
// harness models operator sessions and the ADR-0013 narrowing with it).
func (d *Daemon) SetSSHPeerProbe(fn func() []netip.Addr) { d.decEng.SetSSHPeerProbe(fn) }
