// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Behavior tests for low-and-slow HTTP detection (issue #585): a
// long-window field-level rule (wp-login attempts per day) is served by its
// own persisted matcher counter — written on the hot path only for events
// the matcher accepts, read back by the long-window evaluation — so a
// botnet pacing itself under the 60s and 1h thresholds is still caught,
// and unrelated HTTP traffic never touches the counter table.

import (
	"context"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/rules"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// countingStore wraps the real store and counts the long-window counter
// traffic the daemon generates — the "no counter query on the HTTP hot
// path" guarantee is asserted through it.
type countingStore struct {
	*store.DB
	incr atomic.Int64
	sums atomic.Int64
}

func (c *countingStore) IncrEventCount(ctx context.Context, ip netip.Addr, kind string, bucket int64) error {
	c.incr.Add(1)
	return c.DB.IncrEventCount(ctx, ip, kind, bucket)
}

func (c *countingStore) SumEventCounts(ctx context.Context, ip netip.Addr, kinds []string, since int64) (map[string]int, error) {
	c.sums.Add(1)
	return c.DB.SumEventCounts(ctx, ip, kinds, since)
}

func newHTTPLowSlowDaemon(t *testing.T) (*Daemon, *countingStore) {
	t.Helper()
	db, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cs := &countingStore{DB: db}
	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            false,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:      cs,
		Parsers:    []sdk.Parser{parser.NewNginxParser(slog.Default(), parser.NginxConfig{})},
		SocketPath: "",
		MaxIPs:     100,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, cs
}

func nginxLine(ip netip.Addr, path string) sdk.RawLine {
	return sdk.RawLine{
		Source: "file:/var/log/nginx/access.log",
		Line:   []byte(ip.String() + ` - - [01/Jan/2026:12:00:00 +0000] "POST ` + path + ` HTTP/1.1" 200 4128 "-" "Mozilla/5.0"`),
		At:     time.Now(),
	}
}

// seedCounter backdates n buckets of kind for ip, one per hour step.
func seedCounter(t *testing.T, db *store.DB, ip netip.Addr, kind string, n int) {
	t.Helper()
	now := time.Now()
	for i := 1; i <= n; i++ {
		if err := db.IncrEventCount(context.Background(), ip, kind, store.HourBucket(now.Add(-time.Duration(i)*time.Hour))); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

func TestHTTPLowSlow_WiringKnowsTheDailyRule(t *testing.T) {
	d, _ := newHTTPLowSlowDaemon(t)
	if !d.longFieldKinds["http_request"] {
		t.Fatalf("longFieldKinds = %v, want http_request", d.longFieldKinds)
	}
	if d.longKinds["http_request"] {
		t.Fatalf("http_request must not be counted wholesale (longKinds = %v)", d.longKinds)
	}
	found := false
	for _, k := range d.longRuleWindows[24*time.Hour] {
		if k == rules.LongCounterKind("http_wp_probe_daily") {
			found = true
		}
	}
	if !found {
		t.Fatalf("24h window kinds = %v, want the wp-login daily counter", d.longRuleWindows[24*time.Hour])
	}
}

// TestHTTPLowSlow_PacedBotnetNodeCaughtByDailyRule is the dogfood-host
// case: ~1 wp-login attempt per hour for a day — invisible to the 60s and
// 1h rules — with the 25th attempt arriving live.
func TestHTTPLowSlow_PacedBotnetNodeCaughtByDailyRule(t *testing.T) {
	ctx := context.Background()
	d, cs := newHTTPLowSlowDaemon(t)
	actions := make(chan sdk.Action, 8)
	d.SetActionsSink(actions)

	attacker := netip.MustParseAddr("203.0.113.77")
	seedCounter(t, cs.DB, attacker, rules.LongCounterKind("http_wp_probe_daily"), 24)
	d.processRaw(ctx, nginxLine(attacker, "/wp-login.php"))

	select {
	case got := <-actions:
		if got.IP != attacker || got.Op != "dry_ban" {
			t.Fatalf("action = %+v, want dry_ban for %s", got, attacker)
		}
	default:
		t.Fatal("no action — the paced wp-login attacker escaped the daily rule")
	}
	assertLongRuleFired(t, d, attacker, "http_wp_probe_daily")
	// No short-window rule saw anything: one live event cannot trip them.
	for _, v := range d.evaluateRules(ctx, attacker, false) {
		t.Fatalf("short-window verdict %q on a single event — the daily rule alone must have fired", v.Reason)
	}
}

// TestHTTPLowSlow_OnlyMatchingRequestsTouchTheCounters: an unrelated HTTP
// request writes no counter and triggers no long-window query; a wp-login
// hit writes exactly the rule's counter and evaluates the long windows.
func TestHTTPLowSlow_OnlyMatchingRequestsTouchTheCounters(t *testing.T) {
	ctx := context.Background()
	d, cs := newHTTPLowSlowDaemon(t)
	ip := netip.MustParseAddr("198.51.100.20")

	d.processRaw(ctx, nginxLine(ip, "/index.html"))
	d.processRaw(ctx, nginxLine(ip, "/api/v1/items"))
	if n := cs.incr.Load(); n != 0 {
		t.Fatalf("unrelated requests wrote %d counter row(s), want 0", n)
	}
	if n := cs.sums.Load(); n != 0 {
		t.Fatalf("unrelated requests ran %d long-window quer(ies), want 0", n)
	}

	d.processRaw(ctx, nginxLine(ip, "/wp-login.php"))
	if n := cs.incr.Load(); n != 1 {
		t.Fatalf("wp-login hit wrote %d counter row(s), want exactly 1 (the rule's own)", n)
	}
	if n := cs.sums.Load(); n == 0 {
		t.Fatalf("wp-login hit did not evaluate the long windows")
	}
	sums, err := cs.DB.SumEventCounts(ctx, ip, []string{rules.LongCounterKind("http_wp_probe_daily"), "http_request"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sums[rules.LongCounterKind("http_wp_probe_daily")] != 1 || sums["http_request"] != 0 {
		t.Fatalf("counters = %v, want only the wp-login daily counter at 1", sums)
	}
}

// TestHTTPLowSlow_CountsSurviveRestart: the counter is on disk, so a daemon
// restart mid-campaign forgets nothing.
func TestHTTPLowSlow_CountsSurviveRestart(t *testing.T) {
	ctx := context.Background()
	d1, cs := newHTTPLowSlowDaemon(t)
	attacker := netip.MustParseAddr("203.0.113.78")
	seedCounter(t, cs.DB, attacker, rules.LongCounterKind("http_wp_probe_daily"), 23)
	d1.processRaw(ctx, nginxLine(attacker, "/wp-login.php")) // 24: one short

	// "Restart": a fresh daemon on the same store.
	d2, err := New(Config{Policy: d1.policy, Store: cs, Parsers: []sdk.Parser{parser.NewNginxParser(slog.Default(), parser.NginxConfig{})}, SocketPath: "", MaxIPs: 100})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	actions := make(chan sdk.Action, 8)
	d2.SetActionsSink(actions)
	d2.processRaw(ctx, nginxLine(attacker, "/wp-login.php")) // 25
	select {
	case got := <-actions:
		if got.Op != "dry_ban" {
			t.Fatalf("action = %+v, want dry_ban", got)
		}
	default:
		t.Fatal("restart forgot the wp-login history")
	}
}
