// SPDX-License-Identifier: AGPL-3.0-only

package aggregate_test

// Issue #622, adversarial review of PR #638: the overflow counters must
// (1) keep a field-level rule's count exact while a benign flood CONTINUES
// during the probes, via the Classifier; (2) never count an event older
// than the window (a 60 s rule must not see 60 s + bucket); (3) never
// report Count > 0 for an IP whose raw sample is empty.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/aggregate"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const wpCounter = "rule:http_wp_probe_sustained"

func wpClassifier(ev sdk.Event) []string {
	if ev.Kind == "http_request" && ev.Fields["path"] == "/wp-login.php" {
		return []string{wpCounter}
	}
	return nil
}

// A client at 100 req/s for an hour that ALSO sends one wp-login every
// 2 minutes: the sample spans ~41 s and holds none of the 30 probes, so the
// count must come from the classifier counter — and be exact.
func TestAggregate_ContinuingFloodKeepsFieldRuleCountExact(t *testing.T) {
	a := aggregate.New([]time.Duration{time.Minute, 5 * time.Minute, time.Hour}, 0).WithClassifier(wpClassifier)
	ip := netip.MustParseAddr("203.0.113.103")
	start := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	probes := 0
	for i := 0; i < 360_000; i++ {
		tm := start.Add(time.Duration(i) * 10 * time.Millisecond)
		a.Add(sdk.Event{SourceIP: ip, Kind: "http_request", Time: tm, Fields: map[string]string{"path": "/", "status": "200"}})
		if i%12_000 == 0 {
			a.Add(sdk.Event{SourceIP: ip, Kind: "http_request", Time: tm, Fields: map[string]string{"path": "/wp-login.php", "status": "200"}})
			probes++
		}
	}
	now := start.Add(time.Hour)
	agg := a.Aggregate(ip, time.Hour, now)
	if got := agg.Kinds[wpCounter]; got != probes {
		t.Fatalf("Kinds[%s] = %d, want %d (every probe, sample or evicted, counted exactly)", wpCounter, got, probes)
	}
	if got := agg.Kinds["http_request"]; got != 360_000+probes {
		t.Fatalf("Kinds[http_request] = %d, want %d", got, 360_000+probes)
	}
	if agg.Count != 360_000+probes {
		t.Fatalf("Count = %d, want %d (counter kinds must not inflate Count)", agg.Count, 360_000+probes)
	}
	if n := a.Entries(ip); n > aggregate.DefaultMaxSamples {
		t.Fatalf("retained %d raw events, want ≤ %d", n, aggregate.DefaultMaxSamples)
	}
	// The 5-minute window sees exactly the probes of the last 5 minutes
	// (probes go out at even minutes: 12:56:00 and 12:58:00).
	if got := a.Aggregate(ip, 5*time.Minute, now).Kinds[wpCounter]; got != 2 {
		t.Fatalf("5m Kinds[%s] = %d, want 2", wpCounter, got)
	}
}

// Same host: HTTP flood at several rates plus one ssh_fail every 20 s
// (3/min, below ssh_bruteforce 5/60s). Evaluated the way the daemon does —
// after every event, now = event time — the 60 s count must never exceed
// the exact maximum of 4, whatever the flood rate: an overflow bucket may
// never add events older than the window.
func TestAggregate_OverflowNeverCountsBeyondWindow(t *testing.T) {
	for _, rate := range []int{20, 100, 200} {
		a := aggregate.New([]time.Duration{time.Minute, 5 * time.Minute, time.Hour}, 0)
		ip := netip.MustParseAddr("203.0.113.104")
		start := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
		step := time.Second / time.Duration(rate)
		maxN := 0
		i := 0
		for tm := start; tm.Before(start.Add(4 * time.Minute)); tm = tm.Add(step) {
			a.Add(sdk.Event{SourceIP: ip, Kind: "http_request", Time: tm, Fields: map[string]string{"path": "/"}})
			sshNow := tm.Sub(start)%(20*time.Second) == 0
			if sshNow {
				a.Add(sdk.Event{SourceIP: ip, Kind: "ssh_fail", Time: tm})
			}
			// Evaluate after every ssh_fail and every 50th flood event
			// (the daemon evaluates after every event; sampling keeps the
			// race run short without skipping a bucket edge).
			i++
			if !sshNow && i%50 != 0 {
				continue
			}
			agg := a.Aggregate(ip, time.Minute, tm)
			if n := agg.Kinds["ssh_fail"]; n > maxN {
				maxN = n
			}
			// Sanity on the flood itself: a 60 s window can hold at most
			// rate × 60 + 1 flood events (both edges inclusive).
			if n := agg.Kinds["http_request"]; n > rate*60+1 {
				t.Fatalf("rate %d: 60s Kinds[http_request] = %d > %d — counted events older than the window", rate, n, rate*60+1)
			}
		}
		if maxN > 4 {
			t.Fatalf("rate %d req/s: max 60s Kinds[ssh_fail] = %d, want ≤ 4 (exact) — a minute of overflow slack would fire ssh_bruteforce on 3 failures/min", rate, maxN)
		}
		if a.Entries(ip) > aggregate.DefaultMaxSamples {
			t.Fatalf("rate %d: retained %d raw events", rate, a.Entries(ip))
		}
	}
}

// After Flush evicted every raw event of an IP, no overflow counter may
// survive: a rule must never fire on Count > 0 with an empty Sample.
func TestFlush_NoCountWithoutSample(t *testing.T) {
	a := aggregate.New([]time.Duration{time.Minute, time.Hour}, 0)
	ip := netip.MustParseAddr("203.0.113.105")
	start := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 20_000; i++ { // 200 s at 100 req/s: well past the cap
		a.Add(sdk.Event{SourceIP: ip, Kind: "http_request", Time: start.Add(time.Duration(i) * 10 * time.Millisecond)})
	}
	last := start.Add(200 * time.Second)
	// Flush at a cutoff between the newest evicted event and the newest
	// sample entry's bucket: raw entries older than the cutoff go, and so
	// must every bucket they were counted in.
	a.Flush(context.Background(), last.Add(-30*time.Second))
	agg := a.Aggregate(ip, time.Hour, last)
	if len(agg.Sample) == 0 || agg.Count < len(agg.Sample) {
		t.Fatalf("Count = %d with %d sample events", agg.Count, len(agg.Sample))
	}
	// Now flush everything: the bucket must disappear with its counters.
	a.Flush(context.Background(), last.Add(time.Second))
	agg = a.Aggregate(ip, time.Hour, last.Add(2*time.Second))
	if agg.Count != 0 || len(agg.Sample) != 0 || len(agg.Kinds) != 0 {
		t.Fatalf("after a full flush: Count = %d, Sample = %d, Kinds = %v — counters outlived the raw events", agg.Count, len(agg.Sample), agg.Kinds)
	}
	if a.Len() != 0 {
		t.Fatalf("Len = %d, want 0", a.Len())
	}
}

// Bucket width follows the shortest window (÷12) within [1 s, 1 min].
func TestAggregator_BucketWidth(t *testing.T) {
	cases := []struct {
		windows []time.Duration
		want    time.Duration
	}{
		{[]time.Duration{time.Minute, time.Hour}, 5 * time.Second},
		{[]time.Duration{10 * time.Second}, time.Second},
		{[]time.Duration{time.Hour}, time.Minute},
		{[]time.Duration{4 * time.Second}, time.Second},
	}
	for _, c := range cases {
		if got := aggregate.New(c.windows, 0).Bucket(); got != c.want {
			t.Errorf("windows %v: bucket = %s, want %s", c.windows, got, c.want)
		}
	}
}
