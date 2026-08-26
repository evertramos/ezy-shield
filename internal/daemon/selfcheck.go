// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Periodic hardening self-check (issue #563): the read-only systemd unit
// checks from `doctor` (#213 — AF_NETLINK for the enforcer,
// RuntimeDirectory for both units) plus the functional netlink probe, run
// on a timer inside the daemon so silent-non-enforcement drift is caught
// without the operator remembering to run doctor.
//
// Notification semantics — TRANSITIONS ONLY:
//   - healthy → degraded: ONE critical notification listing the failures,
//     plus an append-only audit entry (selfcheck_degraded);
//   - degraded → healthy: ONE info notification + audit
//     (selfcheck_recovered);
//   - steady state (either direction): silence (debug log only).
//
// N/A results (no systemd, unit not installed, helper predates netcheck)
// count as HEALTHY — script/manual installs stay quiet. Everything is
// read-only: no unit edited, no service restarted, ever.
//
// Opt-out (documented in the config reference): `self_check: {enabled:
// false}` skips the goroutine entirely; `interval` tunes the cadence
// (default 6h, floor 10m).

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/internal/unitcheck"
)

const (
	// defaultSelfCheckInterval is the cadence when config omits interval.
	defaultSelfCheckInterval = 6 * time.Hour
	// selfCheckInitialDelay is the warm-up before the first run: long
	// enough for the enforcer socket to be up, short enough that a broken
	// drop-in surfaces minutes after boot, not hours.
	selfCheckInitialDelay = 5 * time.Minute
)

// runSelfCheck is the self-check loop goroutine. Exits when ctx is done.
func (d *Daemon) runSelfCheck(ctx context.Context) {
	interval := d.selfCheckInterval
	if interval <= 0 {
		interval = defaultSelfCheckInterval
	}
	initial := d.selfCheckInitial
	if initial <= 0 {
		initial = selfCheckInitialDelay
	}

	slog.InfoContext(ctx, "daemon: hardening self-check armed",
		"interval", interval, "first_run_in", initial)

	timer := time.NewTimer(initial)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			d.selfCheckPass(ctx)
			timer.Reset(interval)
		}
	}
}

// selfCheckPass runs one round of checks and handles state transitions.
func (d *Daemon) selfCheckPass(ctx context.Context) {
	results := unitcheck.UnitHardening(ctx)
	// The functional probe only applies when a local nftables enforcer is
	// configured (its socket path is then known).
	if d.selfCheckEnfSocket != "" {
		results = append(results, unitcheck.NetlinkProbe(ctx, d.selfCheckEnfSocket))
	}
	failures := unitcheck.Failures(results)
	healthyNow := len(failures) == 0

	wasHealthy := d.selfCheckHealthy.Load()
	if healthyNow == wasHealthy {
		slog.DebugContext(ctx, "daemon: hardening self-check steady state",
			"healthy", healthyNow, "checks", len(results))
		return
	}
	d.selfCheckHealthy.Store(healthyNow)

	if !healthyNow {
		detail := selfCheckDetail(failures)
		slog.ErrorContext(ctx, "daemon: hardening self-check DEGRADED", "detail", detail)
		if err := d.store.AuditSystem(ctx, "selfcheck_degraded", detail); err != nil {
			slog.ErrorContext(ctx, "daemon: audit selfcheck_degraded failed", "err", err)
		}
		d.notifyCritical(ctx, "hardening self-check DEGRADED: "+detail+
			" — run 'ezyshield doctor' for the full picture and the drop-in fix")
		return
	}

	slog.InfoContext(ctx, "daemon: hardening self-check recovered")
	if err := d.store.AuditSystem(ctx, "selfcheck_recovered", "all hardening checks pass again"); err != nil {
		slog.ErrorContext(ctx, "daemon: audit selfcheck_recovered failed", "err", err)
	}
	d.notifyInfo(ctx, "hardening self-check recovered: all unit checks pass again")
}

// selfCheckDetail joins failure names (with the first hint) into one
// bounded line for the audit/notification.
func selfCheckDetail(failures []unitcheck.Result) string {
	names := make([]string, 0, len(failures))
	for _, f := range failures {
		names = append(names, f.Name)
	}
	detail := strings.Join(names, "; ")
	if len(failures) > 0 && failures[0].Hint != "" {
		hint := failures[0].Hint
		if len(hint) > 300 {
			hint = hint[:300] + "…"
		}
		detail += " — " + hint
	}
	return detail
}
