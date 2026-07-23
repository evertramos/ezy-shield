package daemon

// enfstate.go — honest enforcement-state reporting (issue #174).
//
// status/doctor must never claim protection that is not real. The daemon
// tracks the outcome of every enforcer Ban/Sync and derives one of four
// states from REAL health, not from config alone:
//
//	DISABLED — no enforcer configured (edge-only or observe-only install)
//	DRY-RUN  — enforcer present but armed=false (nothing is enforced)
//	DEGRADED — armed with an enforcer, but its recent Ban/Sync failed
//	ACTIVE   — armed, enforcer configured, last operation succeeded
//
// A failure flips the state to DEGRADED immediately; the next successful
// Ban/Sync flips it back. Every transition is audited.

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// EnforcementState is the coarse health of the enforcement path.
type EnforcementState string

// The four enforcement states, derived from real enforcer health (issue #174).
const (
	EnfActive   EnforcementState = "ACTIVE"   // armed, enforcer healthy
	EnfDryRun   EnforcementState = "DRY-RUN"  // enforcer present, armed=false
	EnfDegraded EnforcementState = "DEGRADED" // armed, enforcer failing
	EnfDisabled EnforcementState = "DISABLED" // no enforcer configured
)

// enfHealth tracks the last enforcer operation outcome. The derived state
// combines this runtime health with the static facts (enforcer present,
// armed) so a config-only reading can never overstate protection.
type enfHealth struct {
	mu       sync.Mutex
	degraded bool   // last Ban/Sync failed
	lastErr  string // the failure detail, for status/doctor/audit
	enforcer string // enforcer name (for messages)
}

// enforcementState derives the current state. hasEnforcer/armed are the
// static facts; the health flag is the runtime truth.
func (d *Daemon) enforcementState() (EnforcementState, string) {
	if d.enforcer == nil {
		return EnfDisabled, ""
	}
	if !d.policy.IsArmed() {
		return EnfDryRun, ""
	}
	d.enfHealth.mu.Lock()
	defer d.enfHealth.mu.Unlock()
	if d.enfHealth.degraded {
		return EnfDegraded, d.enfHealth.lastErr
	}
	return EnfActive, ""
}

// recordEnforceResult updates enforcement health from an enforcer Ban/Sync
// outcome and audits any state transition. op is a short label ("ban",
// "sync") for the audit reason. It is safe for concurrent use.
func (d *Daemon) recordEnforceResult(ctx context.Context, op string, err error) {
	if d.enforcer == nil {
		return
	}
	d.enfHealth.mu.Lock()
	was := d.enfHealth.degraded
	if err != nil {
		d.enfHealth.degraded = true
		d.enfHealth.lastErr = fmt.Sprintf("%s %s: %v", d.enforcer.Name(), op, err)
	} else {
		d.enfHealth.degraded = false
		d.enfHealth.lastErr = ""
	}
	now := d.enfHealth.degraded
	detail := d.enfHealth.lastErr
	d.enfHealth.mu.Unlock()

	if was == now {
		return // no transition
	}
	if now {
		reason := "enforcement DEGRADED — " + detail
		slog.ErrorContext(ctx, "daemon: enforcement state → DEGRADED", "detail", detail)
		d.auditEnfTransition(ctx, "enforce_degraded", reason)
		d.notifyCritical(ctx, "enforcement DEGRADED: "+detail+" — bans may not be applied; check the enforcer")
	} else {
		reason := "enforcement recovered → ACTIVE (" + d.enforcer.Name() + ")"
		slog.InfoContext(ctx, "daemon: enforcement state → ACTIVE (recovered)")
		d.auditEnfTransition(ctx, "enforce_recovered", reason)
	}
}

// auditEnfTransition writes a state-transition record. Uses the system-op
// audit path (ip column "system"), append-only.
func (d *Daemon) auditEnfTransition(ctx context.Context, op, reason string) {
	if auditor, ok := d.store.(interface {
		AuditSystem(context.Context, string, string) error
	}); ok {
		if err := auditor.AuditSystem(ctx, op, reason); err != nil {
			slog.ErrorContext(ctx, "daemon: audit "+op, "err", err)
		}
	}
	d.publishActionEvent(op, "system", 0, 0, reason, "enforcer")
}
