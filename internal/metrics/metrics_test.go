package metrics

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestExposition_Golden pins the exact text format (HELP/TYPE + samples,
// sorted label values).
func TestExposition_Golden(t *testing.T) {
	r := NewRegistry()
	r.BuildInfo("v0.1.0-test")
	c := r.Counter("ezyshield_test_total", "A test counter.")
	c.Add(3)
	lc := r.LabeledCounter("ezyshield_events_total", "Events by parser.", "parser")
	lc.With("ssh").Add(2)
	lc.With("nginx").Inc()
	g := r.Gauge("ezyshield_test_gauge", "A test gauge.")
	g.Set(-7)
	r.GaugeFunc("ezyshield_fn_gauge", "Computed at scrape.", func() int64 { return 42 })

	want := `# HELP ezyshield_build_info Build information; the value is always 1.
# TYPE ezyshield_build_info gauge
ezyshield_build_info{version="v0.1.0-test"} 1
# HELP ezyshield_test_total A test counter.
# TYPE ezyshield_test_total counter
ezyshield_test_total 3
# HELP ezyshield_events_total Events by parser.
# TYPE ezyshield_events_total counter
ezyshield_events_total{parser="nginx"} 1
ezyshield_events_total{parser="ssh"} 2
# HELP ezyshield_test_gauge A test gauge.
# TYPE ezyshield_test_gauge gauge
ezyshield_test_gauge -7
# HELP ezyshield_fn_gauge Computed at scrape.
# TYPE ezyshield_fn_gauge gauge
ezyshield_fn_gauge 42
`
	if got := r.Snapshot(); got != want {
		t.Errorf("exposition mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestConcurrentIncrements pins correctness under -race with many
// goroutines hammering shared counters.
func TestConcurrentIncrements(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("ezyshield_conc_total", "x")
	lc := r.LabeledCounter("ezyshield_conc_labeled_total", "x", "op")
	const goroutines, per = 16, 1000
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				c.Inc()
				lc.With("ban").Inc()
			}
		}()
	}
	wg.Wait()
	if c.Value() != goroutines*per {
		t.Errorf("counter = %d, want %d", c.Value(), goroutines*per)
	}
	if v := lc.With("ban").Value(); v != goroutines*per {
		t.Errorf("labeled = %d, want %d", v, goroutines*per)
	}
}

// TestCardinalityBounded is the lint-style test: label names outside the
// allowlist panic at registration, hostile label values fold to "invalid",
// and the per-metric value cap folds excess into "other".
func TestCardinalityBounded(t *testing.T) {
	r := NewRegistry()

	// 1. Unknown label name → registration panics.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("registering label \"ip\" must panic — IPs are never label values")
			}
		}()
		r.LabeledCounter("ezyshield_bad_total", "x", "ip")
	}()

	// 2. Hostile values fold into "invalid" — never a raw label.
	lc := r.LabeledCounter("ezyshield_vals_total", "x", "op")
	for _, hostile := range []string{
		"192.0.2.1 or 1=1", "a\nb", `x"y`, "", strings.Repeat("z", 200),
	} {
		lc.With(hostile).Inc()
	}
	snap := r.Snapshot()
	if !strings.Contains(snap, `op="invalid"`) {
		t.Errorf("hostile values not folded to invalid:\n%s", snap)
	}
	if strings.Contains(snap, "192.0.2.1") || strings.Contains(snap, "zzzzzzzzzz") {
		t.Errorf("hostile value leaked into exposition:\n%s", snap)
	}

	// 3. Distinct-value cap folds into "other".
	lc2 := r.LabeledCounter("ezyshield_cap_total", "x", "op")
	for i := 0; i < 200; i++ {
		lc2.With(fmt.Sprintf("v%d", i)).Inc()
	}
	snap = r.Snapshot()
	if !strings.Contains(snap, `op="other"`) {
		t.Errorf("value cap did not fold into other:\n%s", snap)
	}
	if c := strings.Count(snap, "ezyshield_cap_total{"); c > 65 {
		t.Errorf("cap breached: %d distinct label values", c)
	}

	// 4. Every registered labeled metric uses an allowlisted label name.
	for name, label := range r.LabelNames() {
		if !AllowedLabels[label] {
			t.Errorf("metric %s uses non-allowlisted label %q", name, label)
		}
	}
}
