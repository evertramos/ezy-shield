// SPDX-License-Identifier: AGPL-3.0-only

package decision_test

// Regression tests for issue #649: while a rule stays saturated in the
// observe band, every evaluation used to append a notify_only audit row —
// 135 rows in one minute for one IP on the dogfood host. The engine now
// audits the RISING EDGE only: the first notify_only for (ip, rule) writes a
// row; repeats of the same rule for the same IP inside the suppression
// window still return Op="notify_only" (so the notifier's own dedup, the
// metrics and the live stream see every event) but write no row. A different
// rule, an elapsed window, or a strike opens a fresh edge.

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// notifyEdgeIP is the TEST-NET-2 client every test in this file evaluates.
var notifyEdgeIP = netip.MustParseAddr("198.51.100.77")

// observeVerdict builds the verdict the rules engine emits for a saturated
// observe-band rule: the count keeps rising with every event, the rule
// identity (the Reason up to the first ':') stays the same.
func observeVerdict(ip netip.Addr, rule string, count int) []sdk.Verdict {
	return []sdk.Verdict{{
		IP:       ip,
		Score:    65, // observe band: ObserveThreshold 40 ≤ 65 < BanThreshold 70
		Category: "scanner",
		Source:   "rules",
		Reason:   fmt.Sprintf("rule/%s: %d events in 1m0s (threshold 15)", rule, count),
	}}
}

// countAudited returns how many Audit calls the mock recorded with op.
func countAudited(st *mockStore, op string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	n := 0
	for _, a := range st.audited {
		if a.Op == op {
			n++
		}
	}
	return n
}

// notifyEdgeEngine returns an engine on a virtual clock the test advances
// through advance; the returned mock counts audit rows.
func notifyEdgeEngine(t *testing.T) (eng *engineOnClock, st *mockStore) {
	t.Helper()
	st = newMock(nil)
	e := mustEngine(t, armedPolicy(), st)
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	ec := &engineOnClock{Engine: e, now: now}
	e.SetClock(ec.clock)
	return ec, st
}

// engineOnClock pairs an Engine with the virtual instant its clock returns.
// Tests advance the clock by calling advance; the closure handed to
// SetClock reads it under a mutex so the concurrency test is race-free.
type engineOnClock struct {
	*decision.Engine
	mu  sync.Mutex
	now time.Time
}

func (c *engineOnClock) clock() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *engineOnClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestNotifyEdge_SaturatedRuleAuditsOnce reproduces the dogfood observation:
// 50 evaluations of one saturated rule must leave exactly ONE notify_only
// audit row, while every evaluation still returns Op="notify_only" with the
// verdict's own Reason (fails on dev with 50 rows).
func TestNotifyEdge_SaturatedRuleAuditsOnce(t *testing.T) {
	eng, st := notifyEdgeEngine(t)
	ctx := context.Background()

	for i := range 50 {
		act, err := eng.Decide(ctx, observeVerdict(notifyEdgeIP, "http_scanner_503", 15+i))
		if err != nil {
			t.Fatalf("Decide #%d: %v", i, err)
		}
		if act.Op != "notify_only" {
			t.Fatalf("Decide #%d: Op=%q, want notify_only (the Action must not change, only the audit row)", i, act.Op)
		}
		if want := fmt.Sprintf("rule/http_scanner_503: %d events in 1m0s (threshold 15)", 15+i); act.Reason != want {
			t.Fatalf("Decide #%d: Reason=%q, want %q", i, act.Reason, want)
		}
		// Each evaluation happens one second apart, well inside the window.
		eng.advance(time.Second)
	}

	if got := countAudited(st, "notify_only"); got != 1 {
		t.Fatalf("notify_only audit rows = %d, want 1 (one row per rising edge, issue #649)", got)
	}
	if len(st.banned) != 0 {
		t.Fatalf("RecordStrike called %d time(s) in the observe band", len(st.banned))
	}
}

// TestNotifyEdge_DifferentRuleOpensNewEdge: a different rule firing for the
// same IP inside the window is a new cause and gets its own row.
func TestNotifyEdge_DifferentRuleOpensNewEdge(t *testing.T) {
	eng, st := notifyEdgeEngine(t)
	ctx := context.Background()

	for i := range 10 {
		if _, err := eng.Decide(ctx, observeVerdict(notifyEdgeIP, "http_scanner_503", 15+i)); err != nil {
			t.Fatalf("Decide: %v", err)
		}
	}
	eng.advance(time.Second)
	if _, err := eng.Decide(ctx, observeVerdict(notifyEdgeIP, "http_probe_404", 30)); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	if got := countAudited(st, "notify_only"); got != 2 {
		t.Fatalf("notify_only audit rows = %d, want 2 (one per rule)", got)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if r := st.audited[1].Reason; r != "rule/http_probe_404: 30 events in 1m0s (threshold 15)" {
		t.Fatalf("second row Reason=%q, want the http_probe_404 verdict", r)
	}
}

// TestNotifyEdge_WindowElapsedOpensNewEdge: once the suppression window has
// passed on the engine clock, the same rule is audited again — the audit
// trail keeps showing that the scanner is still there, once per window.
func TestNotifyEdge_WindowElapsedOpensNewEdge(t *testing.T) {
	eng, st := notifyEdgeEngine(t)
	ctx := context.Background()

	if _, err := eng.Decide(ctx, observeVerdict(notifyEdgeIP, "http_scanner_503", 15)); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	eng.advance(59 * time.Second)
	if _, err := eng.Decide(ctx, observeVerdict(notifyEdgeIP, "http_scanner_503", 60)); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got := countAudited(st, "notify_only"); got != 1 {
		t.Fatalf("notify_only audit rows inside the window = %d, want 1", got)
	}

	eng.advance(2 * time.Second) // 61 s after the first row
	if _, err := eng.Decide(ctx, observeVerdict(notifyEdgeIP, "http_scanner_503", 61)); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got := countAudited(st, "notify_only"); got != 2 {
		t.Fatalf("notify_only audit rows after the window = %d, want 2", got)
	}
}

// TestNotifyEdge_StrikeClearsEdge: a strike (ban) for the IP resets its
// notify edge, so the first observe-band evaluation after the ban ends is
// audited even inside the original window.
func TestNotifyEdge_StrikeClearsEdge(t *testing.T) {
	eng, st := notifyEdgeEngine(t)
	ctx := context.Background()

	if _, err := eng.Decide(ctx, observeVerdict(notifyEdgeIP, "http_scanner_503", 15)); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	eng.advance(time.Second)
	act, err := eng.Decide(ctx, banVerdict(notifyEdgeIP))
	if err != nil {
		t.Fatalf("Decide (ban): %v", err)
	}
	if act.Op != "ban" {
		t.Fatalf("ban verdict Op=%q, want ban", act.Op)
	}

	// The ban ends (row removed by the reaper); the scanner is back in the
	// observe band 5 s after the first notify_only row.
	st.setBanned(notifyEdgeIP, false)
	eng.advance(4 * time.Second)
	if _, err := eng.Decide(ctx, observeVerdict(notifyEdgeIP, "http_scanner_503", 16)); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got := countAudited(st, "notify_only"); got != 2 {
		t.Fatalf("notify_only audit rows = %d, want 2 (edge cleared by the strike)", got)
	}
}

// TestNotifyEdge_ConcurrentEvaluationsAuditOnce: the pipeline and the
// deferred SSH re-check (issue #420) can evaluate the same IP concurrently;
// the edge must still yield exactly one row (run with -race).
func TestNotifyEdge_ConcurrentEvaluationsAuditOnce(t *testing.T) {
	eng, st := notifyEdgeEngine(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range 50 {
				act, err := eng.Decide(ctx, observeVerdict(notifyEdgeIP, "http_scanner_503", 15+g*50+i))
				if err != nil || act.Op != "notify_only" {
					t.Errorf("goroutine %d Decide #%d: op=%q err=%v", g, i, act.Op, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	if got := countAudited(st, "notify_only"); got != 1 {
		t.Fatalf("notify_only audit rows = %d, want 1", got)
	}
}
