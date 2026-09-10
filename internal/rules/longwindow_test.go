// SPDX-License-Identifier: AGPL-3.0-only

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

func TestValidate_LongWindowFieldRuleAccepted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeDropin(t, dir, "50-long-field.yaml", `
rules:
  - name: admin_probe_daily
    kinds: [http_request]
    field: path
    contains: /admin
    window: 86400s
    threshold: 5
    score: 70
    category: scanner
`)
	e, err := rules.New("", dir)
	if err != nil {
		t.Fatalf("a long-window field-level rule must load (issue #585): %v", err)
	}
	// It is served by its own counter kind, not by http_request wholesale.
	daily := e.KindsForLongWindows()[24*time.Hour]
	found := map[string]bool{}
	for _, k := range daily {
		found[k] = true
	}
	if !found[rules.LongCounterKind("admin_probe_daily")] {
		t.Fatalf("24h counter kinds = %v, want %q", daily, rules.LongCounterKind("admin_probe_daily"))
	}
	if found["http_request"] {
		t.Fatalf("24h counter kinds = %v: a field rule must not persist http_request wholesale", daily)
	}
	if !e.LongFieldEventKinds()["http_request"] {
		t.Fatalf("LongFieldEventKinds = %v, want http_request", e.LongFieldEventKinds())
	}
}

func TestValidate_ReservedCounterPrefixRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeDropin(t, dir, "50-bad.yaml", `
rules:
  - name: "rule:sneaky"
    kinds: [ssh_fail]
    window: 60s
    threshold: 5
    score: 70
    category: bruteforce
`)
	if _, err := rules.New("", dir); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("err = %v, want the reserved-prefix rejection", err)
	}
}

// TestLongCounterKinds_MatcherDrivesTheCounter: only an event the rule's
// matcher accepts increments the rule's counter (issue #585) — an unrelated
// HTTP request increments nothing.
func TestLongCounterKinds_MatcherDrivesTheCounter(t *testing.T) {
	t.Parallel()
	e, err := rules.New("", "")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	ip := netip.MustParseAddr("203.0.113.9")
	hit := sdk.Event{SourceIP: ip, Kind: "http_request", Fields: map[string]string{"path": "/wp-login.php", "status": "200"}}
	miss := sdk.Event{SourceIP: ip, Kind: "http_request", Fields: map[string]string{"path": "/index.html", "status": "200"}}
	other := sdk.Event{SourceIP: ip, Kind: "ssh_fail"}
	if got := e.LongCounterKinds(hit); len(got) != 1 || got[0] != rules.LongCounterKind("http_wp_probe_daily") {
		t.Fatalf("hit → %v, want [%s]", got, rules.LongCounterKind("http_wp_probe_daily"))
	}
	if got := e.LongCounterKinds(miss); len(got) != 0 {
		t.Fatalf("miss → %v, want none", got)
	}
	if got := e.LongCounterKinds(other); len(got) != 0 {
		t.Fatalf("ssh event → %v, want none", got)
	}
}

// TestEvaluate_LongFieldRuleReadsItsCounter: the aggregate shape the daemon
// builds from the store — the rule's counter kind, no Sample — fires the
// daily wp-login rule at its threshold; below it, nothing.
func TestEvaluate_LongFieldRuleReadsItsCounter(t *testing.T) {
	t.Parallel()
	e, err := rules.New("", "")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	ip := netip.MustParseAddr("203.0.113.9")
	ck := rules.LongCounterKind("http_wp_probe_daily")
	fire := sdk.Aggregate{IP: ip, Window: 24 * time.Hour, Count: 25, Kinds: map[string]int{ck: 25}}
	var got []string
	for _, v := range e.Evaluate(context.Background(), fire) {
		got = append(got, v.Reason)
	}
	if len(got) != 1 || !strings.Contains(got[0], "rule/http_wp_probe_daily: 25 events") {
		t.Fatalf("verdicts = %v, want exactly the daily wp-login rule", got)
	}
	quiet := sdk.Aggregate{IP: ip, Window: 24 * time.Hour, Count: 24, Kinds: map[string]int{ck: 24}}
	if v := e.Evaluate(context.Background(), quiet); len(v) != 0 {
		t.Fatalf("24 events fired %v, want nothing (threshold 25)", v)
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
