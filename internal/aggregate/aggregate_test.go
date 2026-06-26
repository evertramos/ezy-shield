package aggregate_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/aggregate"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

var (
	ip1 = netip.MustParseAddr("1.2.3.4")
	ip2 = netip.MustParseAddr("5.6.7.8")
	t0  = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
)

func event(ip netip.Addr, kind string, at time.Time) sdk.Event {
	return sdk.Event{SourceIP: ip, Kind: kind, Time: at, Fields: map[string]string{}}
}

func eventWithField(ip netip.Addr, kind string, at time.Time, key, val string) sdk.Event {
	return sdk.Event{SourceIP: ip, Kind: kind, Time: at, Fields: map[string]string{key: val}}
}

func TestAggregate_BasicCount(t *testing.T) {
	a := aggregate.New([]time.Duration{60 * time.Second}, 0)
	now := t0

	for i := 0; i < 3; i++ {
		a.Add(event(ip1, "ssh_fail", now.Add(time.Duration(i)*time.Second)))
	}
	a.Add(event(ip1, "ssh_accept", now.Add(4*time.Second)))

	agg := a.Aggregate(ip1, 60*time.Second, now.Add(10*time.Second))
	if agg.Count != 4 {
		t.Errorf("Count = %d, want 4", agg.Count)
	}
	if agg.Kinds["ssh_fail"] != 3 {
		t.Errorf("Kinds[ssh_fail] = %d, want 3", agg.Kinds["ssh_fail"])
	}
	if agg.Kinds["ssh_accept"] != 1 {
		t.Errorf("Kinds[ssh_accept] = %d, want 1", agg.Kinds["ssh_accept"])
	}
}

func TestAggregate_WindowEviction(t *testing.T) {
	window := 60 * time.Second
	a := aggregate.New([]time.Duration{window}, 0)

	// Event at t0 — falls outside the window when queried at t0+90s.
	a.Add(event(ip1, "ssh_fail", t0))
	// Event at t0+50s — still inside a 60s window queried at t0+90s.
	a.Add(event(ip1, "ssh_fail", t0.Add(50*time.Second)))

	now := t0.Add(90 * time.Second)
	agg := a.Aggregate(ip1, window, now)
	if agg.Count != 1 {
		t.Errorf("Count = %d, want 1 (event at t0 should be evicted)", agg.Count)
	}
}

func TestAggregate_MultipleWindows(t *testing.T) {
	a := aggregate.New([]time.Duration{60 * time.Second, 10 * time.Minute}, 0)
	now := t0.Add(10 * time.Minute)

	// 2 events within the last 60s.
	a.Add(event(ip1, "ssh_fail", now.Add(-30*time.Second)))
	a.Add(event(ip1, "ssh_fail", now.Add(-10*time.Second)))
	// 3 events older than 60s but within 10m.
	a.Add(event(ip1, "ssh_fail", now.Add(-5*time.Minute)))
	a.Add(event(ip1, "ssh_fail", now.Add(-8*time.Minute)))
	a.Add(event(ip1, "ssh_fail", now.Add(-9*time.Minute)))

	agg60 := a.Aggregate(ip1, 60*time.Second, now)
	if agg60.Count != 2 {
		t.Errorf("60s Count = %d, want 2", agg60.Count)
	}

	agg10m := a.Aggregate(ip1, 10*time.Minute, now)
	if agg10m.Count != 5 {
		t.Errorf("10m Count = %d, want 5", agg10m.Count)
	}
}

func TestAggregate_SeparateIPs(t *testing.T) {
	a := aggregate.New([]time.Duration{60 * time.Second}, 0)
	now := t0

	a.Add(event(ip1, "ssh_fail", now))
	a.Add(event(ip2, "ssh_fail", now))
	a.Add(event(ip2, "ssh_fail", now.Add(time.Second)))

	agg1 := a.Aggregate(ip1, 60*time.Second, now.Add(10*time.Second))
	agg2 := a.Aggregate(ip2, 60*time.Second, now.Add(10*time.Second))

	if agg1.Count != 1 {
		t.Errorf("ip1 Count = %d, want 1", agg1.Count)
	}
	if agg2.Count != 2 {
		t.Errorf("ip2 Count = %d, want 2", agg2.Count)
	}
	if agg1.IP != ip1 {
		t.Errorf("ip1 aggregate IP = %v, want %v", agg1.IP, ip1)
	}
}

func TestAggregate_EmptyIP(t *testing.T) {
	a := aggregate.New([]time.Duration{60 * time.Second}, 0)
	agg := a.Aggregate(ip1, 60*time.Second, t0)
	if agg.Count != 0 {
		t.Errorf("empty Count = %d, want 0", agg.Count)
	}
	if len(agg.Kinds) != 0 {
		t.Errorf("empty Kinds = %v, want empty", agg.Kinds)
	}
}

func TestAggregate_SampleCap(t *testing.T) {
	cap := 5
	a := aggregate.New([]time.Duration{60 * time.Second}, cap)
	now := t0

	for i := 0; i < 10; i++ {
		a.Add(event(ip1, "ssh_fail", now.Add(time.Duration(i)*time.Second)))
	}

	agg := a.Aggregate(ip1, 60*time.Second, now.Add(30*time.Second))
	if len(agg.Sample) != cap {
		t.Errorf("Sample len = %d, want %d", len(agg.Sample), cap)
	}
	// Count must still be accurate (not limited by cap).
	if agg.Count != 10 {
		t.Errorf("Count = %d, want 10 (sample cap must not affect count)", agg.Count)
	}
}

func TestAggregate_SampleContainsFieldValues(t *testing.T) {
	a := aggregate.New([]time.Duration{60 * time.Second}, 100)
	now := t0

	a.Add(eventWithField(ip1, "http_request", now, "status", "404"))
	a.Add(eventWithField(ip1, "http_request", now.Add(time.Second), "status", "200"))

	agg := a.Aggregate(ip1, 60*time.Second, now.Add(10*time.Second))
	if len(agg.Sample) != 2 {
		t.Fatalf("Sample len = %d, want 2", len(agg.Sample))
	}
	if agg.Sample[0].Fields["status"] != "404" {
		t.Errorf("Sample[0].status = %q, want 404", agg.Sample[0].Fields["status"])
	}
}

func TestAggregate_Flush(t *testing.T) {
	a := aggregate.New([]time.Duration{60 * time.Second}, 0)
	now := t0

	a.Add(event(ip1, "ssh_fail", now))
	a.Add(event(ip2, "ssh_fail", now))

	// Flush with a cutoff that removes all events.
	a.Flush(context.Background(), now.Add(time.Hour))

	agg1 := a.Aggregate(ip1, 60*time.Second, now.Add(time.Hour))
	if agg1.Count != 0 {
		t.Errorf("after flush ip1 Count = %d, want 0", agg1.Count)
	}
}

func TestAggregate_FlushKeepsRecentEvents(t *testing.T) {
	a := aggregate.New([]time.Duration{10 * time.Minute}, 0)
	now := t0

	// Old event — should be flushed.
	a.Add(event(ip1, "ssh_fail", now.Add(-15*time.Minute)))
	// Recent event — should survive.
	a.Add(event(ip1, "ssh_fail", now.Add(-1*time.Minute)))

	a.Flush(context.Background(), now.Add(-10*time.Minute))

	agg := a.Aggregate(ip1, 10*time.Minute, now)
	if agg.Count != 1 {
		t.Errorf("after partial flush Count = %d, want 1", agg.Count)
	}
}

func TestAggregate_ConcurrentSafety(t *testing.T) {
	a := aggregate.New([]time.Duration{60 * time.Second}, 0)
	now := t0

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a.Add(event(ip1, "ssh_fail", now.Add(time.Duration(i)*time.Millisecond)))
		}(i)
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.Aggregate(ip1, 60*time.Second, now.Add(time.Minute))
		}()
	}

	wg.Wait()
	agg := a.Aggregate(ip1, 60*time.Second, now.Add(time.Minute))
	if agg.Count != 50 {
		t.Errorf("concurrent Count = %d, want 50", agg.Count)
	}
}

func TestAggregate_WindowField(t *testing.T) {
	a := aggregate.New([]time.Duration{60 * time.Second}, 0)
	a.Add(event(ip1, "ssh_fail", t0))

	agg := a.Aggregate(ip1, 60*time.Second, t0.Add(10*time.Second))
	if agg.Window != 60*time.Second {
		t.Errorf("Window = %v, want 60s", agg.Window)
	}
	if agg.IP != ip1 {
		t.Errorf("IP = %v, want %v", agg.IP, ip1)
	}
}

func TestAggregator_Windows(t *testing.T) {
	windows := []time.Duration{60 * time.Second, 10 * time.Minute}
	a := aggregate.New(windows, 0)
	got := a.Windows()
	if len(got) != len(windows) {
		t.Errorf("Windows() len = %d, want %d", len(got), len(windows))
	}
	for i, w := range windows {
		if got[i] != w {
			t.Errorf("Windows()[%d] = %v, want %v", i, got[i], w)
		}
	}
}
