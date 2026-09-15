// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Config.Now drives every timing rule on the ban path from ONE virtual
// clock (issue #605, Phase 1): the store's expires_at and active-ban
// predicate, the engine's grace window, the daemon's counter buckets and
// re-check deadlines. Without it the timing defects of #599/#603 could only
// be reproduced with sleeps and real seconds.

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

// virtualClock is a settable clock shared by the store, engine and daemon.
type virtualClock struct{ t time.Time }

func (c *virtualClock) now() time.Time          { return c.t }
func (c *virtualClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestVirtualClock_DrivesBanTTLAcrossStoreEngineAndDaemon(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clk := &virtualClock{t: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            true,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:      db,
		Enforcer:   &fakeEnforcer{},
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default())},
		SocketPath: "",
		MaxIPs:     100,
		Now:        clk.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.decEng.SetSSHPeerProbe(func() []netip.Addr { return nil })
	actions := make(chan sdk.Action, 16)
	d.SetActionsSink(actions)
	attacker := netip.MustParseAddr("203.0.113.61")

	// A burst at virtual noon earns strike 1 (5 min).
	feedBurst(ctx, d, attacker, 6)
	var ban sdk.Action
	for len(actions) > 0 {
		if a := <-actions; a.Op == "ban" {
			ban = a
		}
	}
	if ban.Strike != 1 || ban.TTL != 5*time.Minute {
		t.Fatalf("first ban = %+v, want strike 1 / 5m", ban)
	}
	// The store stamped expires_at from the virtual clock, not wall time.
	if _, _, _, found, err := db.GetBanInfo(ctx, attacker); err != nil || !found {
		t.Fatalf("ban not active at virtual noon: found=%v err=%v", found, err)
	}

	// Four minutes later the ban is still active — no sleep involved.
	clk.advance(4 * time.Minute)
	if _, _, _, found, _ := db.GetBanInfo(ctx, attacker); !found {
		t.Fatalf("ban expired early on the virtual clock")
	}

	// Past the TTL: not active for the engine (#603) even before the reaper
	// runs; the reaper, fed the same clock, removes the row.
	clk.advance(2 * time.Minute)
	if _, _, _, found, _ := db.GetBanInfo(ctx, attacker); found {
		t.Fatalf("expired ban still read as active on the virtual clock")
	}
	if n, err := db.ExpireBans(ctx, clk.now()); err != nil || n != 1 {
		t.Fatalf("ExpireBans on the virtual clock: n=%d err=%v, want 1", n, err)
	}

	// A fresh burst now becomes strike 2: the decision engine compares the
	// escalation window and the active-ban guard against the same clock.
	feedBurst(ctx, d, attacker, 6)
	var second sdk.Action
	for len(actions) > 0 {
		if a := <-actions; a.Op == "ban" {
			second = a
		}
	}
	if second.Strike != 2 {
		t.Fatalf("second ban = %+v, want strike 2", second)
	}
}

func TestVirtualClock_HourlyCountersBucketOnVirtualTime(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clk := &virtualClock{t: time.Date(2026, 9, 10, 12, 30, 0, 0, time.UTC)}
	d, err := New(Config{
		Policy:     &config.Policy{Armed: false, BanThreshold: config.DefaultBanThreshold, ObserveThreshold: config.DefaultObserveThreshold, MaxBansPerMinute: config.DefaultMaxBansPerMinute, Strikes: config.DefaultStrikes},
		Store:      db,
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default())},
		SocketPath: "",
		MaxIPs:     100,
		Now:        clk.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ip := netip.MustParseAddr("203.0.113.62")
	d.processRaw(ctx, sshFailLine(ip))
	clk.advance(time.Hour) // 13:30 — a different hourly bucket
	d.processRaw(ctx, sshFailLine(ip))

	sums, err := db.SumEventCounts(ctx, ip, []string{"ssh_fail"}, store.HourBucket(clk.now().Add(-30*time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if sums["ssh_fail"] != 1 {
		t.Fatalf("13:xx bucket = %d, want 1 (the 12:xx event must sit in the earlier virtual bucket)", sums["ssh_fail"])
	}
	all, _ := db.SumEventCounts(ctx, ip, []string{"ssh_fail"}, 0)
	if all["ssh_fail"] != 2 {
		t.Fatalf("total = %d, want 2", all["ssh_fail"])
	}
}
