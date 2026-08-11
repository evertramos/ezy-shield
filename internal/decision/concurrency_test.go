package decision_test

// concurrency_test.go — the deferred SSH re-check (issue #420) made Decide a
// concurrent entry point for the first time: runSSHRecheck calls it from its
// own goroutine while the pipeline goroutine may be deciding the same IP. The
// active-ban guard and the GetStrikeCount→RecordStrike sequence are a
// check-then-act, so without per-IP serialisation both callers could pass the
// guard and each record a strike + return Op="ban" — two strike rows and a
// duplicate Enforcer.Ban for one offender. This test pins the invariant:
// concurrent Decide calls for one IP yield exactly one strike and one ban.

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDecide_ConcurrentPipelineAndRecheck_SingleStrikeAndBan reproduces the
// TOCTOU deterministically with store hooks (no flaky sleeps): caller 1 is
// parked inside the critical section (at its GetStrikeCount) while caller 2 is
// launched for the SAME IP. Caller 1 is released only once caller 2 has had its
// chance to pass the active-ban guard. With the per-IP strike lock caller 2 is
// blocked before the guard until caller 1's RecordStrike lands, so it observes
// the ban row and suppresses → exactly one strike + one ban. Without the lock
// caller 2 reads "not banned" concurrently and both record → two strikes / two
// bans (the regression this guards against).
func TestDecide_ConcurrentPipelineAndRecheck_SingleStrikeAndBan(t *testing.T) {
	t.Setenv("SSH_CLIENT", "")

	st := newMock(nil)
	eng := mustEngine(t, armedPolicy(), st)
	// Hermetic: no real /proc probe, no SSH peers — both callers reach the
	// strike path.
	eng.SetSSHPeerProbe(func() []netip.Addr { return nil })

	target := netip.MustParseAddr("203.0.113.200") // TEST-NET-3

	// Park the FIRST caller to reach GetStrikeCount inside the critical section
	// (past the active-ban guard, before RecordStrike). Subsequent callers pass
	// through untouched.
	c1Entered := make(chan struct{})
	release := make(chan struct{})
	var firstStrikeSeen int32
	st.onGetStrikeCount = func(netip.Addr) {
		if atomic.AddInt32(&firstStrikeSeen, 1) == 1 {
			close(c1Entered)
			<-release
		}
	}

	// Signal when a SECOND caller passes the active-ban guard (GetBanInfo). In
	// the buggy engine this happens concurrently; with the fix the second caller
	// is blocked on the per-IP lock and never reaches the guard before release.
	c2PastGuard := make(chan struct{}, 1)
	var guardCalls int32
	st.onGetBanInfo = func(netip.Addr) {
		if atomic.AddInt32(&guardCalls, 1) == 2 {
			select {
			case c2PastGuard <- struct{}{}:
			default:
			}
		}
	}

	ops := make(chan string, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	// Caller 1: the pipeline.
	go func() {
		defer wg.Done()
		act, err := eng.Decide(context.Background(), banVerdict(target))
		if err != nil {
			t.Errorf("caller1 Decide: %v", err)
		}
		ops <- act.Op
	}()

	<-c1Entered // caller 1 is parked inside the critical section

	// Caller 2: the deferred SSH re-check, concurrent for the SAME IP.
	go func() {
		defer wg.Done()
		act, err := eng.Decide(context.Background(), banVerdict(target))
		if err != nil {
			t.Errorf("caller2 Decide: %v", err)
		}
		ops <- act.Op
	}()

	// Let caller 2 reach (and, in the buggy engine, pass) the guard before
	// releasing caller 1. With the fix caller 2 is stuck on the lock and the
	// guard signal never comes, so fall back to a bounded wait.
	select {
	case <-c2PastGuard:
	case <-time.After(time.Second):
	}
	close(release)
	wg.Wait()
	close(ops)

	got := make(map[string]int)
	for op := range ops {
		got[op]++
	}

	if n := len(st.banned); n != 1 {
		t.Fatalf("RecordStrike calls = %d, want exactly 1 (concurrent Decide double-strike / double-ban)", n)
	}
	if got["ban"] != 1 || got["already_banned"] != 1 {
		t.Fatalf("Decide ops = %v, want exactly one \"ban\" and one \"already_banned\"", got)
	}
}
