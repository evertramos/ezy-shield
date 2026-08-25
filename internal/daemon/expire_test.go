package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// Tests for the ban-TTL expiry loop (issue #327): runExpireBans had zero
// coverage and no injectable tick, even though its post-expiry
// syncEnforcer reconcile is the ONLY mechanism that removes expired bans
// from edge enforcers with no native TTL. If a refactor dropped that
// reconcile, expired bans would stay enforced at the edge indefinitely —
// these tests make that refactor fail.

func newExpireDaemon(t *testing.T, enf *fakeEnforcer) (*Daemon, *store.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	policy := &config.Policy{
		Armed:            true,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}
	d, err := New(Config{
		Policy:     policy,
		Store:      db,
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default())},
		Enforcer:   enf,
		SocketPath: "",
		MaxIPs:     100,
		ExpireTick: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, db
}

// TestRunExpireBans_RemovesExpiredAndReconcilesEnforcer: an elapsed timed
// ban is removed from the store by the loop, the permanent ban survives,
// and the post-expiry Sync hands the enforcer a target set WITHOUT the
// expired IP — the edge-cleanup contract (§8 SECURITY-REVIEW: test the
// unban/expiry path, not just the ban path).
func TestRunExpireBans_RemovesExpiredAndReconcilesEnforcer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	timed := netip.MustParseAddr("203.0.113.20")
	perm := netip.MustParseAddr("203.0.113.21")
	enf := &fakeEnforcer{}
	d, db := newExpireDaemon(t, enf)

	// A timed ban already past its TTL, and a permanent one (TTL 0).
	if err := db.RecordStrike(ctx, sdk.Action{IP: timed, Op: "ban", TTL: time.Millisecond,
		Strike: 1, Reason: "timed"}); err != nil {
		t.Fatalf("RecordStrike timed: %v", err)
	}
	if err := db.RecordStrike(ctx, sdk.Action{IP: perm, Op: "ban", TTL: 0, Permanent: true,
		Strike: 5, Reason: "perm"}); err != nil {
		t.Fatalf("RecordStrike perm: %v", err)
	}
	time.Sleep(5 * time.Millisecond) // let the timed ban elapse

	go d.runExpireBans(ctx)

	if !waitFor(2*time.Second, func() bool { return enf.SyncCount() >= 1 }) {
		t.Fatal("post-expiry syncEnforcer never ran — edge enforcers would keep the expired ban forever")
	}

	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 1 || bans[0].IP != perm {
		t.Fatalf("bans after expiry = %+v, want only the permanent %v", bans, perm)
	}

	for _, tgt := range enf.LastSync() {
		if tgt.IP == timed {
			t.Fatalf("expired IP %v still present in the reconciled enforcer target set", timed)
		}
	}
	found := false
	for _, tgt := range enf.LastSync() {
		if tgt.IP == perm {
			found = true
		}
	}
	if !found {
		t.Errorf("permanent ban %v missing from the reconciled target set: %+v", perm, enf.LastSync())
	}
}

// TestRunExpireBans_NoExpiries_NoSync: with nothing to expire the loop
// must not churn the enforcer — Sync fires only when n > 0.
func TestRunExpireBans_NoExpiries_NoSync(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	perm := netip.MustParseAddr("203.0.113.22")
	enf := &fakeEnforcer{}
	d, db := newExpireDaemon(t, enf)
	if err := db.RecordStrike(ctx, sdk.Action{IP: perm, Op: "ban", TTL: 0, Permanent: true,
		Strike: 5, Reason: "perm"}); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}

	go d.runExpireBans(ctx)
	time.Sleep(100 * time.Millisecond) // ~10 ticks

	if n := enf.SyncCount(); n != 0 {
		t.Errorf("Sync ran %d time(s) with nothing expired — pointless enforcer churn", n)
	}
	bans, err := db.ActiveBans(ctx)
	if err != nil || len(bans) != 1 {
		t.Fatalf("permanent ban disturbed: bans=%+v err=%v", bans, err)
	}
}
