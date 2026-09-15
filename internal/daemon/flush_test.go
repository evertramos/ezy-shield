// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Regression test for issue #610: the aggregator flush must evict by the
// LONGEST in-memory window, whatever the rule order is. With the embedded
// rules the windows come out as [60s, 3600s, 300s]; flushing by the last
// one dropped every hourly rule's history each tick.

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

func TestFlush_EvictsByLongestWindow(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clk := &virtualClock{t: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
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
	// Precondition of the bug: the last in-memory window is shorter than the longest.
	ws := d.agg.Windows()
	if ws[len(ws)-1] >= d.agg.MaxWindow() {
		t.Skipf("windows %v: last is the longest, the bug shape is absent", ws)
	}
	ip := netip.MustParseAddr("203.0.113.9")
	// Stamped at the VIRTUAL clock: the journald source has no timestamp,
	// so the parser uses RawLine.At as the event time.
	d.processRaw(ctx, sdk.RawLine{Source: "journald:sshd", At: clk.now(),
		Line: []byte("Failed password for root from " + ip.String() + " port 40122 ssh2")})
	clk.advance(40 * time.Minute)
	d.flushAggregates(ctx, clk.now())
	if got := d.agg.Aggregate(ip, time.Hour, clk.now()).Count; got != 1 {
		t.Fatalf("40-minute-old event evicted by the flush (count in 1h window = %d, want 1)", got)
	}
	clk.advance(25 * time.Minute) // 65 min old: past the longest window
	d.flushAggregates(ctx, clk.now())
	if got := d.agg.Aggregate(ip, time.Hour, clk.now()).Count; got != 0 {
		t.Fatalf("event older than the longest window survived the flush (count = %d)", got)
	}
}
