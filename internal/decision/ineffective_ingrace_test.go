// SPDX-License-Identifier: AGPL-3.0-only

package decision_test

// Regression tests for issue #586: the ban_ineffective diagnostic also fires
// by VOLUME inside the grace window — a flood right after a ban is not the
// latency the grace exists to absorb — through the same once-per-ban
// compare-and-set as the post-grace trigger, carrying a phase so the
// delivery can name the right remedy.

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/decision"
)

// recDiag records every BanIneffective firing the engine delivers.
type recDiag struct {
	mu    sync.Mutex
	fired []decision.BanIneffectiveDiag
}

func (r *recDiag) BanIneffective(_ context.Context, d decision.BanIneffectiveDiag) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fired = append(r.fired, d)
}
func (r *recDiag) BanIneffectivePermanent(context.Context, netip.Addr, int) {}
func (r *recDiag) all() []decision.BanIneffectiveDiag {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]decision.BanIneffectiveDiag(nil), r.fired...)
}

func inGracePolicy(threshold int) *config.Policy {
	p := armedPolicy()
	p.BanIneffectiveMinEventsInGrace = &threshold
	return p
}

// TestBanIneffective_InGraceVolume_Fires: 200 suppressed events 30 s after
// the ban (inside the 90 s grace) fire the diagnostic once, phase in_grace.
func TestBanIneffective_InGraceVolume_Fires(t *testing.T) {
	buf := captureLogs(t)
	st := newMock(nil)
	st.setBannedWithTime(ip1, time.Now().Add(-30*time.Second), 2)
	engine := mustEngine(t, inGracePolicy(200), st)
	rec := &recDiag{}
	engine.SetDiagnostics(rec)

	suppressN(t, engine, ip1, 199)
	if got := strings.Count(buf.String(), diagMsg); got != 0 {
		t.Fatalf("fired %d time(s) at 199 in-grace events, want 0", got)
	}
	suppressN(t, engine, ip1, 1) // 200th
	if got := strings.Count(buf.String(), diagMsg); got != 1 {
		t.Fatalf("fired %d time(s) at 200 in-grace events, want exactly 1", got)
	}
	if !strings.Contains(buf.String(), "phase=in_grace") {
		t.Errorf("WARN missing phase=in_grace; log:\n%s", buf.String())
	}
	fired := rec.all()
	if len(fired) != 1 || fired[0].Phase != decision.PhaseInGrace || fired[0].EventsInGrace != 200 || fired[0].EventsAfterGrace != 0 {
		t.Fatalf("diag = %+v, want one in_grace firing with 200 in-grace events", fired)
	}
	// Fire-once across BOTH paths: the grace elapses and post-grace events
	// keep coming — the same ban must not fire again.
	st.setBannedWithTime(ip1, time.Now().Add(-10*time.Minute), 2)
	suppressN(t, engine, ip1, 5)
	if got := strings.Count(buf.String(), diagMsg); got != 1 {
		t.Fatalf("fired %d time(s) after the grace on an already-fired ban, want still 1", got)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.supFired[ip1.String()] || !st.hadIneff[ip1.String()] {
		t.Error("in-grace firing did not persist ineffective_fired / had_ineffective")
	}
}

// TestBanIneffective_InGraceVolume_Disabled: 0 turns the volume trigger
// off — a flood inside the grace is silent, and the post-grace trigger is
// untouched.
func TestBanIneffective_InGraceVolume_Disabled(t *testing.T) {
	buf := captureLogs(t)
	st := newMock(nil)
	st.setBannedWithTime(ip1, time.Now().Add(-30*time.Second), 1)
	engine := mustEngine(t, inGracePolicy(0), st)

	suppressN(t, engine, ip1, 300)
	if got := strings.Count(buf.String(), diagMsg); got != 0 {
		t.Fatalf("fired %d time(s) with the volume trigger disabled, want 0", got)
	}
	st.setBannedWithTime(ip1, time.Now().Add(-10*time.Minute), 1)
	suppressN(t, engine, ip1, 3) // post-grace threshold (3) unchanged
	if got := strings.Count(buf.String(), diagMsg); got != 1 {
		t.Fatalf("post-grace trigger fired %d time(s), want 1", got)
	}
	if !strings.Contains(buf.String(), "phase=post_grace") {
		t.Errorf("WARN missing phase=post_grace; log:\n%s", buf.String())
	}
}

// TestBanIneffective_InGraceVolume_DryRunSilent: armed-only, like the
// post-grace trigger (ADR-0009 §5).
func TestBanIneffective_InGraceVolume_DryRunSilent(t *testing.T) {
	buf := captureLogs(t)
	st := newMock(nil)
	st.setBannedWithTime(ip1, time.Now().Add(-30*time.Second), 1)
	pol := inGracePolicy(10)
	pol.Armed = false
	engine := mustEngine(t, pol, st)

	suppressN(t, engine, ip1, 20)
	if got := strings.Count(buf.String(), diagMsg); got != 0 {
		t.Fatalf("fired %d time(s) in dry-run, want 0", got)
	}
}

func TestPolicy_InGraceIneffectiveThreshold(t *testing.T) {
	zero, neg, ten := 0, -5, 10
	for _, tc := range []struct {
		name string
		v    *int
		want int
	}{
		{"unset → default", nil, config.DefaultBanIneffectiveMinEventsInGrace},
		{"0 → disabled", &zero, 0},
		{"negative → 1", &neg, 1},
		{"explicit", &ten, 10},
	} {
		p := &config.Policy{BanIneffectiveMinEventsInGrace: tc.v}
		if got := p.InGraceIneffectiveThreshold(); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}
