package daemon

// Tests for the panic button (issue #176): disable_all disarms, clears every
// active ban while preserving history, pushes the empty state to the
// enforcers, audits everything — and reports partial failure honestly.

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func newPanicDaemon(t *testing.T, enf sdk.Enforcer) (*Daemon, *store.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
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
		Store:      db,
		Enforcer:   enf,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, db
}

func seedBans(t *testing.T, db *store.DB, ips ...string) {
	t.Helper()
	ctx := context.Background()
	for _, ip := range ips {
		if err := db.RecordStrike(ctx, sdk.Action{
			IP: netip.MustParseAddr(ip), Op: "ban", TTL: time.Hour, Strike: 1, Reason: "seed",
		}); err != nil {
			t.Fatalf("RecordStrike: %v", err)
		}
	}
}

func TestDisableAll_DisarmsClearsAndSyncsEmpty(t *testing.T) {
	enf := &fakeSyncEnforcer{}
	d, db := newPanicDaemon(t, enf)
	ctx := context.Background()
	seedBans(t, db, "192.0.2.10", "192.0.2.11", "192.0.2.12")

	resp := d.handleDisableAll(ctx)
	if !resp.OK {
		t.Fatalf("disable_all failed: %s", resp.Error)
	}
	var data DisableAllData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !data.Disarmed || data.BansRemoved != 3 || !data.EnforcersSynced {
		t.Fatalf("data = %+v, want disarmed, 3 removed, synced", data)
	}
	if d.policy.IsArmed() {
		t.Fatal("daemon must be disarmed")
	}

	// The enforcers received the EMPTY desired state (local flush + edge
	// emptied through the reconcile path).
	enf.mu.Lock()
	last := enf.syncTargets[len(enf.syncTargets)-1]
	enf.mu.Unlock()
	if len(last) != 0 {
		t.Fatalf("last Sync carried %d targets, want 0", len(last))
	}

	// bans_active empty; strike history and offenders preserved.
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 0 {
		t.Fatalf("active bans left = %d, want 0", len(bans))
	}
	strikes, err := db.StrikesForIP(ctx, netip.MustParseAddr("192.0.2.10"), 10)
	if err != nil || len(strikes) != 1 {
		t.Fatalf("strike history must survive: %v, %v", strikes, err)
	}

	// Audited: the disarm and the summary row with the count.
	entries, err := db.ListAuditLog(ctx, 100)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	var sawDisarm, sawSummary bool
	for _, e := range entries {
		if e.Op == "disarm" {
			sawDisarm = true
		}
		if e.Op == "disable_all" && strings.Contains(e.Reason, "removed 3 active bans") {
			sawSummary = true
		}
	}
	if !sawDisarm || !sawSummary {
		t.Fatalf("audit incomplete: disarm=%v summary=%v", sawDisarm, sawSummary)
	}
}

// failingSyncEnforcer fails Sync to exercise the honest partial-failure path.
type failingSyncEnforcer struct{ fakeEnforcer }

func (f *failingSyncEnforcer) Sync(_ context.Context, _ []sdk.Target) error {
	return context.DeadlineExceeded
}

func TestDisableAll_PartialFailureIsHonest(t *testing.T) {
	d, db := newPanicDaemon(t, &failingSyncEnforcer{})
	ctx := context.Background()
	seedBans(t, db, "192.0.2.20")

	resp := d.handleDisableAll(ctx)
	if resp.OK {
		t.Fatal("a failed enforcer sync must not report full success")
	}
	if !strings.Contains(resp.Error, "may linger") {
		t.Fatalf("error = %q, want the lingering-blocks warning", resp.Error)
	}
	var data DisableAllData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !data.Disarmed || data.BansRemoved != 1 || data.EnforcersSynced {
		t.Fatalf("data = %+v, want disarmed+cleared but NOT synced", data)
	}
}

func TestDisableAll_ReArmDoesNotReapply(t *testing.T) {
	enf := &fakeSyncEnforcer{}
	d, db := newPanicDaemon(t, enf)
	ctx := context.Background()
	seedBans(t, db, "192.0.2.30", "192.0.2.31")

	if resp := d.handleDisableAll(ctx); !resp.OK {
		t.Fatalf("disable_all: %s", resp.Error)
	}
	// Re-arm (runtime flip; the arm verb's pre-flight is out of scope here)
	// and reconcile — nothing may come back.
	d.policy.SetArmed(true)
	if err := d.syncEnforcer(ctx); err != nil {
		t.Fatalf("syncEnforcer: %v", err)
	}
	enf.mu.Lock()
	last := enf.syncTargets[len(enf.syncTargets)-1]
	enf.mu.Unlock()
	if len(last) != 0 {
		t.Fatalf("re-arm re-applied %d bans, want 0 (rows were cleared)", len(last))
	}
}
