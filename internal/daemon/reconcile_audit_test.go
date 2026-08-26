// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Tests for the reconcile-repair audit trail (issue #214): when a periodic
// reconcile has to repair store↔kernel drift (the signature of a mid-write
// interruption), the daemon appends an "enforce_reconcile" audit_log entry —
// but never for the boot reconcile, where re-adding every persisted ban is
// expected recovery, and never when the enforcer converged with no repairs.

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// fakeRepairEnforcer implements sdk.Enforcer plus enforce.SyncRepairReporter,
// replaying a scripted sequence of repair reports (one per Sync call).
type fakeRepairEnforcer struct {
	fakeEnforcer
	mu      sync.Mutex
	reports []repairReport
	calls   int
}

type repairReport struct {
	added, removed int
	first          bool
}

func (f *fakeRepairEnforcer) Sync(_ context.Context, _ []sdk.Target) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls < len(f.reports) {
		f.calls++
	}
	return nil
}

func (f *fakeRepairEnforcer) LastSyncRepairs() (added, removed int, firstSync bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := f.calls - 1
	if idx < 0 || idx >= len(f.reports) {
		return 0, 0, false
	}
	r := f.reports[idx]
	return r.added, r.removed, r.first
}

var _ enforce.SyncRepairReporter = (*fakeRepairEnforcer)(nil)

func countReconcileAudits(t *testing.T, db *store.DB) (n int, lastReason string) {
	t.Helper()
	entries, err := db.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	for _, e := range entries {
		if e.Op == "enforce_reconcile" {
			if n == 0 {
				lastReason = e.Reason
			}
			n++
		}
	}
	return n, lastReason
}

func TestSyncEnforcer_AuditsNonBootRepairsOnly(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.RecordStrike(ctx, sdk.Action{
		IP: netip.MustParseAddr("192.0.2.10"), Op: "ban", TTL: time.Hour, Strike: 1, Reason: "real",
	}); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}

	enf := &fakeRepairEnforcer{reports: []repairReport{
		{added: 1, removed: 0, first: true},  // boot reconcile: expected recovery
		{added: 0, removed: 0, first: false}, // converged: nothing to report
		{added: 2, removed: 1, first: false}, // real drift: must be audited
	}}
	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            true,
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

	// Boot reconcile repairs but is flagged firstSync — no audit entry.
	if err := d.syncEnforcer(ctx); err != nil {
		t.Fatalf("syncEnforcer (boot): %v", err)
	}
	if n, _ := countReconcileAudits(t, db); n != 0 {
		t.Fatalf("boot reconcile wrote %d enforce_reconcile audits, want 0", n)
	}

	// Converged reconcile — still no audit entry.
	if err := d.syncEnforcer(ctx); err != nil {
		t.Fatalf("syncEnforcer (converged): %v", err)
	}
	if n, _ := countReconcileAudits(t, db); n != 0 {
		t.Fatalf("converged reconcile wrote %d enforce_reconcile audits, want 0", n)
	}

	// Post-boot drift — exactly one audit entry naming both directions.
	if err := d.syncEnforcer(ctx); err != nil {
		t.Fatalf("syncEnforcer (drift): %v", err)
	}
	n, reason := countReconcileAudits(t, db)
	if n != 1 {
		t.Fatalf("drift reconcile wrote %d enforce_reconcile audits, want 1", n)
	}
	if !strings.Contains(reason, "re-added 2") || !strings.Contains(reason, "removed 1") {
		t.Fatalf("audit reason = %q, want the repair counts in it", reason)
	}
}
