// SPDX-License-Identifier: AGPL-3.0-only

package aggregate_test

// Regression tests for issue #622: per-IP retention must be bounded by the
// sample cap whatever the client's rate, kind-level counts must stay exact
// for the retained horizon, and the retained sample must be the NEWEST
// events (the oldest-first cap of E3-2 hid current traffic from field-level
// rules and evidence).

import (
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/aggregate"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// busyHour feeds one client at 100 req/s for a virtual hour (360k events)
// into an aggregator with the daemon's window shape.
func busyHour(a *aggregate.Aggregator, ip netip.Addr, start time.Time) {
	for i := 0; i < 360_000; i++ {
		a.Add(sdk.Event{SourceIP: ip, Kind: "http_request", Time: start.Add(time.Duration(i) * 10 * time.Millisecond),
			Fields: map[string]string{"path": "/", "status": "200"}})
	}
}

func TestAggregate_BusyIPRetentionIsBounded(t *testing.T) {
	a := aggregate.New([]time.Duration{time.Minute, 5 * time.Minute, time.Hour}, 0)
	ip := netip.MustParseAddr("203.0.113.100")
	start := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	busyHour(a, ip, start)
	now := start.Add(time.Hour)

	if n := a.Entries(ip); n > aggregate.DefaultMaxSamples {
		t.Fatalf("retained %d raw events for one IP, want ≤ %d (issue #622)", n, aggregate.DefaultMaxSamples)
	}
	// Kind-level counts stay exact on the retained horizon.
	if got := a.Aggregate(ip, time.Hour, now).Count; got != 360_000 {
		t.Fatalf("1h count = %d, want 360000 exactly", got)
	}
	if got := a.Aggregate(ip, 10*time.Minute, now).Count; got != 60_000 {
		t.Fatalf("10m count = %d, want 60000 exactly", got)
	}
	if got := a.Aggregate(ip, time.Minute, now).Count; got != 6_000 {
		t.Fatalf("1m count = %d, want 6000 exactly", got)
	}
}

// TestAggregate_SampleKeepsNewestEvents: after a flood of benign requests
// the sample must still show the attacker's current requests, or every
// field-level hourly rule is blind to busy IPs (E3-2).
func TestAggregate_SampleKeepsNewestEvents(t *testing.T) {
	a := aggregate.New([]time.Duration{time.Hour}, 0)
	ip := netip.MustParseAddr("203.0.113.101")
	start := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5000; i++ {
		a.Add(sdk.Event{SourceIP: ip, Kind: "http_request", Time: start.Add(time.Duration(i) * 60 * time.Millisecond),
			Fields: map[string]string{"path": "/", "status": "200"}})
	}
	for i := 0; i < 12; i++ {
		a.Add(sdk.Event{SourceIP: ip, Kind: "http_request", Time: start.Add(10*time.Minute + time.Duration(i)*time.Minute),
			Fields: map[string]string{"path": "/wp-login.php", "status": "200"}})
	}
	agg := a.Aggregate(ip, time.Hour, start.Add(30*time.Minute))
	hits := 0
	for _, ev := range agg.Sample {
		if ev.Fields["path"] == "/wp-login.php" {
			hits++
		}
	}
	if hits != 12 {
		t.Fatalf("sample holds %d of the 12 newest wp-login events, want 12 (sample must keep the newest, not the oldest)", hits)
	}
	if len(agg.Sample) > aggregate.DefaultMaxSamples {
		t.Fatalf("sample len %d exceeds the cap", len(agg.Sample))
	}
	// Arrival order is preserved inside the sample.
	for i := 1; i < len(agg.Sample); i++ {
		if agg.Sample[i].Time.Before(agg.Sample[i-1].Time) {
			t.Fatalf("sample not in arrival order at %d", i)
		}
	}
}

func BenchmarkAggregate_BusyIP(b *testing.B) {
	a := aggregate.New([]time.Duration{time.Minute, 5 * time.Minute, time.Hour}, 0)
	ip := netip.MustParseAddr("203.0.113.102")
	start := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	busyHour(a, ip, start)
	now := start.Add(time.Hour)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.Aggregate(ip, time.Hour, now)
	}
}
