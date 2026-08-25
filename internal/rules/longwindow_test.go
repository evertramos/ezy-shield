package rules_test

// Tests for the long-window split (issue #134): the KindsForLongWindows
// accessor and the kind-level-only validation for windows above the cutoff.

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/rules"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestKindsForLongWindows_EmbeddedBase(t *testing.T) {
	t.Parallel()
	e, err := rules.New("", "")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	long := e.KindsForLongWindows()
	daily, ok := long[24*time.Hour]
	if !ok {
		t.Fatalf("embedded base must expose a 24h long window, got %v", long)
	}
	weekly, ok := long[7*24*time.Hour]
	if !ok {
		t.Fatalf("embedded base must expose a 7d long window, got %v", long)
	}
	for _, kinds := range [][]string{daily, weekly} {
		found := map[string]bool{}
		for _, k := range kinds {
			found[k] = true
		}
		if !found["ssh_fail"] || !found["ssh_invalid_user"] {
			t.Fatalf("long-window kinds = %v, want ssh_fail + ssh_invalid_user", kinds)
		}
	}
	// No window at or below the cutoff may appear.
	for w := range long {
		if w <= rules.LongWindowCutoff {
			t.Fatalf("window %s is not long (cutoff %s)", w, rules.LongWindowCutoff)
		}
	}
}

func TestValidate_LongWindowFieldRuleRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeDropin(t, dir, "50-bad.yaml", `
rules:
  - name: bad_long_field
    kinds: [http_request]
    field: path
    contains: /admin
    window: 86400s
    threshold: 5
    score: 70
    category: scanner
`)
	_, err := rules.New("", dir)
	if err == nil || !strings.Contains(err.Error(), "persistent counters") {
		t.Fatalf("err = %v, want the kind-level-only rejection for long windows", err)
	}
	if !strings.Contains(err.Error(), "50-bad.yaml") {
		t.Fatalf("err = %v, must name the offending drop-in", err)
	}
}

func TestEvaluate_DailyRuleFiresFromCounterAggregate(t *testing.T) {
	t.Parallel()
	e, err := rules.New("", "")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	// The exact shape the daemon builds from SumEventCounts: kind counts
	// only, no Sample. Evaluate is reused unmodified (design constraint).
	agg := sdk.Aggregate{
		IP:     netip.MustParseAddr("192.0.2.50"),
		Window: 24 * time.Hour,
		Count:  5,
		Kinds:  map[string]int{"ssh_fail": 3, "ssh_invalid_user": 2},
	}
	verdicts := e.Evaluate(context.Background(), agg)
	var fired bool
	for _, v := range verdicts {
		if strings.Contains(v.Reason, "ssh_bruteforce_daily") {
			fired = true
			if v.Score < 70 {
				t.Fatalf("daily verdict score = %d, want >= ban threshold", v.Score)
			}
		}
	}
	if !fired {
		t.Fatalf("ssh_bruteforce_daily did not fire on %v, verdicts: %v", agg.Kinds, verdicts)
	}

	// Below threshold: silent.
	agg.Kinds = map[string]int{"ssh_fail": 4}
	agg.Count = 4
	for _, v := range e.Evaluate(context.Background(), agg) {
		if strings.Contains(v.Reason, "ssh_bruteforce_daily") {
			t.Fatalf("daily rule fired below threshold: %v", v)
		}
	}
}
