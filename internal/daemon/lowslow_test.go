package daemon

// Behavior tests for low-and-slow SSH detection (issue #134): the persistent
// hourly counters catch attackers pacing themselves beyond the in-memory
// windows, survive daemon restarts, never widen the RAM aggregator, and stay
// bounded by allowlist supremacy and the dry-run default.

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/rules"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// newLowSlowDaemon builds a pipeline-ready daemon (dry-run policy, SSH
// parser, no collectors — tests drive processRaw directly) on db.
func newLowSlowDaemon(t *testing.T, db *store.DB, allowlist []string) *Daemon {
	t.Helper()
	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            false,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
			Allowlist:        allowlist,
		},
		Store:      db,
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default())},
		SocketPath: "",
		MaxIPs:     100,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func sshFailLine(ip netip.Addr) sdk.RawLine {
	return sdk.RawLine{
		Source: "journald:sshd",
		Line:   []byte("Failed password for root from " + ip.String() + " port 40122 ssh2"),
		At:     time.Now(),
	}
}

// assertLongRuleFired asserts that the long-window evaluation for ip
// produces a verdict from the named rule (Action.Reason carries only
// score/category, so rule identity is asserted at the verdict layer).
func assertLongRuleFired(t *testing.T, d *Daemon, ip netip.Addr, rule string) {
	t.Helper()
	for _, v := range d.evaluateLongRules(context.Background(), ip, time.Now()) {
		if strings.Contains(v.Reason, rule) {
			return
		}
	}
	t.Fatalf("long-window rule %q did not fire for %s", rule, ip)
}

// seedHourlyFailures backdates n ssh_fail counter buckets, one per hour
// step, mimicking an attacker pacing 1 attempt/hour (or 1/day with a 24h
// step) — history the in-memory aggregator can no longer see.
func seedHourlyFailures(t *testing.T, db *store.DB, ip netip.Addr, n int, step time.Duration) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	for i := 1; i <= n; i++ {
		bucket := store.HourBucket(now.Add(-time.Duration(i) * step))
		if err := db.IncrEventCount(ctx, ip, "ssh_fail", bucket); err != nil {
			t.Fatalf("seed IncrEventCount: %v", err)
		}
	}
}

func TestLowSlow_AggregatorKeepsNoLongWindows(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	d := newLowSlowDaemon(t, db, nil)

	// The RAM aggregator must hold only fine windows — no 24h/7d horizon of
	// events in memory (the whole point of the persistent counters).
	for _, w := range d.agg.Windows() {
		if w > rules.LongWindowCutoff {
			t.Fatalf("in-memory aggregator holds long window %s", w)
		}
	}
	// And the long-window plumbing must know the embedded daily/weekly rules.
	if _, ok := d.longRuleWindows[24*time.Hour]; !ok {
		t.Fatalf("longRuleWindows = %v, want the 24h window", d.longRuleWindows)
	}
	if !d.longKinds["ssh_fail"] || !d.longKinds["ssh_invalid_user"] {
		t.Fatalf("longKinds = %v", d.longKinds)
	}
}

func TestLowSlow_OnePerHourAttackerCaughtByDailyRule(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	d := newLowSlowDaemon(t, db, nil)
	actions := make(chan sdk.Action, 8)
	d.SetActionsSink(actions)

	attacker := netip.MustParseAddr("192.0.2.60")
	// 4 failures over the last 4 hours (1/hour) — invisible to the 60s and
	// 1h in-memory rules at this pacing…
	seedHourlyFailures(t, db, attacker, 4, time.Hour)
	// …then the 5th attempt arrives live.
	d.processRaw(ctx, sshFailLine(attacker))

	select {
	case got := <-actions:
		if got.IP != attacker || got.Op != "dry_ban" {
			t.Fatalf("action = %+v, want dry_ban for %s", got, attacker)
		}
	default:
		t.Fatal("no action produced — the 1/hour attacker escaped the daily rule")
	}
	assertLongRuleFired(t, d, attacker, "ssh_bruteforce_daily")
}

func TestLowSlow_OncePerDayRetrierCaughtByWeeklyRule(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	d := newLowSlowDaemon(t, db, nil)
	actions := make(chan sdk.Action, 8)
	d.SetActionsSink(actions)

	// The #384 scenario: one wrong login a day. 4 days of history + today's
	// attempt = 5 in the 7d window.
	retrier := netip.MustParseAddr("192.0.2.61")
	seedHourlyFailures(t, db, retrier, 4, 24*time.Hour)
	d.processRaw(ctx, sshFailLine(retrier))

	select {
	case got := <-actions:
		if got.IP != retrier || got.Op != "dry_ban" {
			t.Fatalf("action = %+v, want dry_ban for %s", got, retrier)
		}
	default:
		t.Fatal("no action — the once-a-day retrier escaped the weekly rule")
	}
	assertLongRuleFired(t, d, retrier, "ssh_bruteforce_weekly")

	// Anti-false-positive discriminator: a fumbler with 2 failures days ago
	// plus one today (3 total) stays below every threshold.
	fumbler := netip.MustParseAddr("192.0.2.62")
	seedHourlyFailures(t, db, fumbler, 2, 24*time.Hour)
	d.processRaw(ctx, sshFailLine(fumbler))
	select {
	case got := <-actions:
		t.Fatalf("fumbler with 3 spread failures was actioned: %+v", got)
	default:
	}
}

func TestLowSlow_CountsSurviveRestart(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	attacker := netip.MustParseAddr("192.0.2.63")

	// First daemon lifetime: 4 slow failures land in the counters.
	d1 := newLowSlowDaemon(t, db, nil)
	seedHourlyFailures(t, db, attacker, 2, time.Hour)
	d1.processRaw(ctx, sshFailLine(attacker))
	d1.processRaw(ctx, sshFailLine(attacker))

	// "Restart": a fresh daemon on the same store. The in-memory aggregator
	// starts empty; only the persistent counters remember the history.
	d2 := newLowSlowDaemon(t, db, nil)
	actions := make(chan sdk.Action, 8)
	d2.SetActionsSink(actions)
	d2.processRaw(ctx, sshFailLine(attacker)) // 5th failure overall

	select {
	case got := <-actions:
		if got.IP != attacker || got.Op != "dry_ban" {
			t.Fatalf("action = %+v, want dry_ban from persisted counts", got)
		}
	default:
		t.Fatal("no action after restart — counters did not survive")
	}
	assertLongRuleFired(t, d2, attacker, "ssh_bruteforce_daily")
}

func TestLowSlow_AllowlistStillSuppresses(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	office := netip.MustParseAddr("198.51.100.10")
	d := newLowSlowDaemon(t, db, []string{"198.51.100.0/24"})
	actions := make(chan sdk.Action, 8)
	d.SetActionsSink(actions)

	seedHourlyFailures(t, db, office, 10, time.Hour)
	d.processRaw(ctx, sshFailLine(office))

	select {
	case got := <-actions:
		if got.Op == "ban" || got.Op == "dry_ban" {
			t.Fatalf("allowlisted IP actioned by long-window rule: %+v", got)
		}
	default: // no action: allowlist supremacy held
	}
}

func TestLowSlow_FastBurstStillCaughtByBurstRule(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	d := newLowSlowDaemon(t, db, nil)
	actions := make(chan sdk.Action, 8)
	d.SetActionsSink(actions)

	attacker := netip.MustParseAddr("192.0.2.64")
	for range 5 {
		d.processRaw(ctx, sshFailLine(attacker))
	}
	select {
	case got := <-actions:
		if got.IP != attacker || got.Op != "dry_ban" || got.Strike != 1 {
			t.Fatalf("action = %+v, want strike-1 dry_ban for the burst", got)
		}
	default:
		t.Fatal("burst attacker not actioned")
	}
}
