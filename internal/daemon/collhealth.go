// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// collhealth.go — honest observation-path reporting (issue #456), the
// collector-side sibling of enfstate.go (issue #174).
//
// Supervision itself — restart with capped backoff, panic recovery, the
// one-shot critical alert at collectorFailureAlert() — is runCollector
// (issue #305). What was still missing is visibility: a collector that
// cannot read its source (the field case, #454: journalctl exiting 1 with
// "insufficient permissions") kept failing quietly in the journal while
// `ezyshield status` reported `enforcement: ACTIVE` — protection claimed,
// nothing observed. This file records the outcomes the supervisor sees and
// derives a collectors_state for status: OK / DEGRADED / NONE, with the
// failing collectors named. Degraded/recovered transitions are audited
// through the same append-only system-op path as enforcement transitions.

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
)

// CollectorsState is the coarse health of the observation path.
type CollectorsState string

// The three observation states (issue #456).
const (
	CollOK       CollectorsState = "OK"       // every collector reading (or failing too briefly to matter)
	CollDegraded CollectorsState = "DEGRADED" // at least one collector repeatedly failing to read
	CollNone     CollectorsState = "NONE"     // no collectors configured — nothing is observed
)

// collHealth tracks per-collector runtime health, keyed by collectorName.
type collHealth struct {
	mu sync.Mutex
	st map[string]*collState
}

type collState struct {
	failures int    // consecutive failures, mirroring the supervisor's counter
	lastErr  string // most recent failure detail
	degraded bool
}

// recordCollectorFailure stores the supervisor's latest failure observation
// for name. The collector flips to degraded at the same threshold as the
// supervisor's one-shot critical alert (collectorFailureAlert), so status
// and the notification always tell the same story; the transition is
// audited here (the alert itself stays in runCollector — no double
// notification).
func (d *Daemon) recordCollectorFailure(ctx context.Context, name string, failures int, err error) {
	d.collHealth.mu.Lock()
	if d.collHealth.st == nil {
		d.collHealth.st = map[string]*collState{}
	}
	s := d.collHealth.st[name]
	if s == nil {
		s = &collState{}
		d.collHealth.st[name] = s
	}
	s.failures = failures
	s.lastErr = err.Error()
	was := s.degraded
	if failures >= d.collectorFailureAlert() {
		s.degraded = true
	}
	now := s.degraded
	detail := s.lastErr
	d.collHealth.mu.Unlock()

	if !was && now {
		reason := fmt.Sprintf("observation DEGRADED — collector %q is not reading (%d consecutive failures): %s",
			name, failures, detail)
		slog.ErrorContext(ctx, "daemon: collectors state → DEGRADED", "collector", name, "detail", detail)
		d.auditCollTransition(ctx, "collector_degraded", reason)
	}
}

// recordCollectorHealthy clears name's failure state after a run survived
// the supervisor's stable-runtime window, auditing the recovery when it was
// degraded.
func (d *Daemon) recordCollectorHealthy(ctx context.Context, name string) {
	d.collHealth.mu.Lock()
	s := d.collHealth.st[name]
	if s == nil {
		d.collHealth.mu.Unlock()
		return
	}
	was := s.degraded
	s.failures = 0
	s.lastErr = ""
	s.degraded = false
	d.collHealth.mu.Unlock()

	if was {
		reason := "collector " + name + " recovered — reading again"
		slog.InfoContext(ctx, "daemon: collectors state → OK (recovered)", "collector", name)
		d.auditCollTransition(ctx, "collector_recovered", reason)
	}
}

// collectorsState derives the aggregate observation health for status.
// Deterministic output: failing collectors are listed sorted by name.
func (d *Daemon) collectorsState() (CollectorsState, string) {
	if len(d.collectors) == 0 {
		return CollNone, "no collectors configured — nothing is being observed"
	}
	d.collHealth.mu.Lock()
	defer d.collHealth.mu.Unlock()
	var failing []string
	for name, s := range d.collHealth.st {
		if s.degraded {
			failing = append(failing,
				fmt.Sprintf("%s is not reading (%d consecutive failures: %s)", name, s.failures, s.lastErr))
		}
	}
	if len(failing) == 0 {
		return CollOK, ""
	}
	sort.Strings(failing)
	return CollDegraded, strings.Join(failing, "; ")
}

// auditCollTransition writes an observation state-transition record via the
// same append-only system-op audit path as enforcement transitions
// (auditEnfTransition, enfstate.go).
func (d *Daemon) auditCollTransition(ctx context.Context, op, reason string) {
	if auditor, ok := d.store.(interface {
		AuditSystem(context.Context, string, string) error
	}); ok {
		if err := auditor.AuditSystem(ctx, op, reason); err != nil {
			slog.ErrorContext(ctx, "daemon: audit "+op, "err", err)
		}
	}
	d.publishActionEvent(op, "system", 0, 0, reason, "collector")
}
