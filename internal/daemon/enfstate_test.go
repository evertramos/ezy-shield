package daemon

// Tests for the honest enforcement-state reporting (issue #174): the state
// is derived from real enforcer health, a failing enforcer flips it to
// DEGRADED within one reconcile/ban and recovery flips it back, and every
// transition is audited.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// flakyEnforcer fails Ban/Sync while failing is set. Toggle it to simulate
// an enforcer going down and recovering.
type flakyEnforcer struct {
	mu      sync.Mutex
	failing bool
	bans    int
	syncs   int
}

func (f *flakyEnforcer) setFailing(v bool) { f.mu.Lock(); f.failing = v; f.mu.Unlock() }
func (f *flakyEnforcer) Name() string      { return "flaky" }
func (f *flakyEnforcer) err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failing {
		return errors.New("nftables: operation not permitted")
	}
	return nil
}
func (f *flakyEnforcer) Ban(_ context.Context, _ sdk.Target) error {
	f.mu.Lock()
	f.bans++
	f.mu.Unlock()
	return f.err()
}
func (f *flakyEnforcer) Unban(_ context.Context, _ sdk.Target) error { return f.err() }
func (f *flakyEnforcer) Sync(_ context.Context, _ []sdk.Target) error {
	f.mu.Lock()
	f.syncs++
	f.mu.Unlock()
	return f.err()
}

func newEnfStateDaemon(t *testing.T, enf sdk.Enforcer, armed bool) (*Daemon, *store.DB) {
	t.Helper()
	db, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            armed,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:      db,
		Enforcer:   enf,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, db
}

func TestEnforcementState_DerivedFromRealFacts(t *testing.T) {
	t.Parallel()

	// DISABLED: no enforcer.
	d, _ := newEnfStateDaemon(t, nil, true)
	if s, _ := d.enforcementState(); s != EnfDisabled {
		t.Errorf("no enforcer: state = %s, want DISABLED", s)
	}

	// DRY-RUN: enforcer present but not armed.
	d, _ = newEnfStateDaemon(t, &flakyEnforcer{}, false)
	if s, _ := d.enforcementState(); s != EnfDryRun {
		t.Errorf("unarmed: state = %s, want DRY-RUN", s)
	}

	// ACTIVE: armed, enforcer present, no failure recorded yet.
	d, _ = newEnfStateDaemon(t, &flakyEnforcer{}, true)
	if s, _ := d.enforcementState(); s != EnfActive {
		t.Errorf("armed + healthy: state = %s, want ACTIVE", s)
	}
}

func TestEnforcementState_FlipsDegradedThenRecovers(t *testing.T) {
	t.Parallel()
	enf := &flakyEnforcer{failing: true}
	d, db := newEnfStateDaemon(t, enf, true)
	ctx := context.Background()

	// A failing ban flips the state to DEGRADED within that one operation.
	d.dispatch(ctx, sdk.Action{IP: netip.MustParseAddr("203.0.113.1"), Op: "ban", Strike: 1, TTL: 0})
	if s, detail := d.enforcementState(); s != EnfDegraded {
		t.Fatalf("after failing ban: state = %s, want DEGRADED", s)
	} else if detail == "" {
		t.Error("DEGRADED state carries no detail")
	}

	// The enforcer recovers; the next reconcile flips it back to ACTIVE.
	enf.setFailing(false)
	if err := d.syncEnforcer(ctx); err != nil {
		t.Fatalf("syncEnforcer after recovery: %v", err)
	}
	if s, _ := d.enforcementState(); s != EnfActive {
		t.Fatalf("after recovery reconcile: state = %s, want ACTIVE", s)
	}

	// Both transitions were audited.
	entries, err := db.ListAuditLog(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	var degraded, recovered bool
	for _, e := range entries {
		switch e.Op {
		case "enforce_degraded":
			degraded = true
		case "enforce_recovered":
			recovered = true
		}
	}
	if !degraded || !recovered {
		t.Errorf("audit transitions: degraded=%v recovered=%v, want both", degraded, recovered)
	}
}

func TestEnforcementState_NoAuditWithoutTransition(t *testing.T) {
	t.Parallel()
	enf := &flakyEnforcer{failing: false}
	d, db := newEnfStateDaemon(t, enf, true)
	ctx := context.Background()

	// Three successful bans: state stays ACTIVE, no transition audited.
	for i := 0; i < 3; i++ {
		d.recordEnforceResult(ctx, "ban", nil)
	}
	entries, _ := db.ListAuditLog(ctx, 50)
	for _, e := range entries {
		if e.Op == "enforce_degraded" || e.Op == "enforce_recovered" {
			t.Errorf("unexpected transition audit with no state change: %s", e.Op)
		}
	}
}

func TestHandleStatus_ReportsEnforcementState(t *testing.T) {
	t.Parallel()
	enf := &flakyEnforcer{failing: true}
	d, _ := newEnfStateDaemon(t, enf, true)
	ctx := context.Background()

	d.recordEnforceResult(ctx, "sync", errors.New("boom"))

	resp := d.handleStatus(ctx)
	if !resp.OK {
		t.Fatalf("status: %s", resp.Error)
	}
	var sd StatusData
	if err := json.Unmarshal(resp.Data, &sd); err != nil {
		t.Fatal(err)
	}
	if sd.EnforcementState != string(EnfDegraded) {
		t.Errorf("status EnforcementState = %q, want DEGRADED", sd.EnforcementState)
	}
	if sd.EnforcementDetail == "" {
		t.Error("DEGRADED status carries no detail for the operator")
	}
}

// TestEnforcementState_ProbeFlipsWithoutTraffic covers the staleness gap
// the periodic probe exists for: with no new bans and no expiries, a dying
// enforcer must still flip ACTIVE→DEGRADED within one probe interval, and
// a recovering one DEGRADED→ACTIVE — no traffic required.
func TestEnforcementState_ProbeFlipsWithoutTraffic(t *testing.T) {
	t.Parallel()
	enf := &flakyEnforcer{}
	db, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            true,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:        db,
		Enforcer:     enf,
		EnfProbeTick: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.runEnforceProbe(ctx)

	waitForState := func(want EnforcementState) {
		t.Helper()
		deadline := time.After(2 * time.Second)
		for {
			if s, _ := d.enforcementState(); s == want {
				return
			}
			select {
			case <-deadline:
				s, detail := d.enforcementState()
				t.Fatalf("state = %s (%s), want %s", s, detail, want)
			case <-time.After(time.Millisecond):
			}
		}
	}

	// Healthy start; the enforcer dies with zero traffic → probe degrades.
	enf.setFailing(true)
	waitForState(EnfDegraded)

	// It recovers with zero traffic → probe restores ACTIVE.
	enf.setFailing(false)
	waitForState(EnfActive)
}

// TestEnforcementState_GateRefusalIsNotIllHealth: the centralized allowlist
// gate (PR #252) refusing a Ban is the safety backstop working — it must
// not flip the enforcement state to DEGRADED or claim the enforcer failed.
func TestEnforcementState_GateRefusalIsNotIllHealth(t *testing.T) {
	t.Parallel()
	d, _ := newEnfStateDaemon(t, &flakyEnforcer{}, true)
	ctx := context.Background()

	gateErr := fmt.Errorf("enforce/gate: refusing to ban 192.0.2.1 (allowlisted): %w", enforce.ErrGateRefused)
	d.recordEnforceResult(ctx, "ban", gateErr)

	if s, detail := d.enforcementState(); s != EnfActive {
		t.Fatalf("after gate refusal: state = %s (%s), want ACTIVE (refusal is not enforcer ill-health)", s, detail)
	}
}
