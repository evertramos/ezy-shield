package daemon

// Tests for the enforcement boundary of ADR-0009 §5 (issue #145): simulated
// dry-run bans live in bans_active but must NEVER reach an enforcer — not
// via startup sync, not after the operator flips armed=true and restarts.

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// fakeSyncEnforcer records every target handed to Sync.
type fakeSyncEnforcer struct {
	fakeEnforcer
	mu          sync.Mutex
	syncTargets [][]sdk.Target
}

func (f *fakeSyncEnforcer) Sync(_ context.Context, want []sdk.Target) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]sdk.Target, len(want))
	copy(cp, want)
	f.syncTargets = append(f.syncTargets, cp)
	return nil
}

func TestSyncEnforcer_SkipsSimulatedBans(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	real := netip.MustParseAddr("192.0.2.10")
	simulated := netip.MustParseAddr("192.0.2.20")

	// One real ban (recorded while armed) and one simulated dry-run ban.
	if err := db.RecordStrike(ctx, sdk.Action{
		IP: real, Op: "ban", TTL: time.Hour, Strike: 1, Reason: "real",
	}); err != nil {
		t.Fatalf("RecordStrike real: %v", err)
	}
	if err := db.RecordStrike(ctx, sdk.Action{
		IP: simulated, Op: "dry_ban", TTL: time.Hour, Strike: 1, Reason: "simulated",
	}); err != nil {
		t.Fatalf("RecordStrike dry: %v", err)
	}

	enf := &fakeSyncEnforcer{}
	d, err := New(Config{
		// Armed=true is the dangerous scenario: the operator observed in
		// dry-run, armed, and restarted — leftover simulated bans must not
		// materialise as firewall rules.
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

	if err := d.syncEnforcer(ctx); err != nil {
		t.Fatalf("syncEnforcer: %v", err)
	}

	enf.mu.Lock()
	defer enf.mu.Unlock()
	if len(enf.syncTargets) != 1 {
		t.Fatalf("Sync calls = %d, want 1", len(enf.syncTargets))
	}
	got := enf.syncTargets[0]
	if len(got) != 1 || got[0].IP != real {
		t.Fatalf("Sync targets = %v, want exactly [%s] — a simulated ban reached the enforcer", got, real)
	}
}

func TestHandleStatus_SeparatesSimulatedFromActive(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.RecordStrike(ctx, sdk.Action{
		IP: netip.MustParseAddr("192.0.2.10"), Op: "ban", TTL: time.Hour, Strike: 1, Reason: "real",
	}); err != nil {
		t.Fatalf("RecordStrike real: %v", err)
	}
	for _, ip := range []string{"192.0.2.20", "192.0.2.21"} {
		if err := db.RecordStrike(ctx, sdk.Action{
			IP: netip.MustParseAddr(ip), Op: "dry_ban", TTL: time.Hour, Strike: 1, Reason: "simulated",
		}); err != nil {
			t.Fatalf("RecordStrike dry %s: %v", ip, err)
		}
	}

	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            false,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:      db,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	resp := d.handleStatus(ctx)
	if !resp.OK {
		t.Fatalf("handleStatus error: %s", resp.Error)
	}
	var sd StatusData
	if err := json.Unmarshal(resp.Data, &sd); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if sd.ActiveBans != 1 {
		t.Errorf("ActiveBans = %d, want 1 — simulated bans must not count as active protection", sd.ActiveBans)
	}
	if sd.SimulatedBans != 2 {
		t.Errorf("SimulatedBans = %d, want 2", sd.SimulatedBans)
	}
}
