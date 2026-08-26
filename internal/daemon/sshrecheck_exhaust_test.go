// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Regression tests for issue #559: a peer that HOLDS its SSH socket in
// ESTABLISHED (sshd "Timeout before authentication" pattern) outlasts the
// deferred re-check retry budget. The exhaustion must be loud (WARN, parity
// with the queue-full path) and queryable (offender row + audit entry, so
// `report <ip>` no longer answers "no records") — while the anti-lockout
// invariant stays untouched (zero bans, zero strikes).

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncLogBuffer is a goroutine-safe slog sink: the re-check loop logs from
// its own goroutine while the test reads, so a plain bytes.Buffer races.
type syncLogBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncLogBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncLogBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureSlogSync swaps slog.Default for a synchronized capture buffer.
func captureSlogSync(t *testing.T) *syncLogBuffer {
	t.Helper()
	buf := &syncLogBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// TestSSHRecheck_BudgetExhaustion_LoudAndQueryable drives the exact kylian
// scenario: burst crosses ban_threshold, every re-check finds the peer
// still ESTABLISHED, the budget runs out.
func TestSSHRecheck_BudgetExhaustion_LoudAndQueryable(t *testing.T) {
	buf := captureSlogSync(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attacker := netip.MustParseAddr("203.0.113.45")
	enf := &fakeEnforcer{}
	// The peer NEVER disconnects — the socket-holding attacker.
	d, db := newRecheckDaemon(t, enf, func() []netip.Addr {
		return []netip.Addr{attacker}
	})

	go d.runSSHRecheck(ctx)
	feedBurst(ctx, d, attacker, 6)

	if d.sshRecheck.len() == 0 {
		t.Fatalf("re-check was never armed")
	}
	// Budget: sshRecheckMaxAttempts × 20ms delay ≈ 300ms; wait for the
	// queue to drain via exhaustion.
	if !waitFor(3*time.Second, func() bool { return d.sshRecheck.len() == 0 }) {
		t.Fatalf("re-check queue never drained")
	}

	// 1. Loud: the WARN mirrors the queue-full message.
	if !waitFor(time.Second, func() bool {
		return strings.Contains(buf.String(), "ssh re-check retry budget exhausted")
	}) {
		t.Fatalf("no exhaustion WARN logged; log:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "attempts=") {
		t.Errorf("WARN must carry the attempts count; log:\n%s", buf.String())
	}

	// 2. Queryable: the offenders row exists (the exact gate report checks) …
	off, err := db.GetOffender(ctx, attacker)
	if err != nil {
		t.Fatalf("GetOffender: %v", err)
	}
	if off == nil {
		t.Fatalf("no offender row after exhaustion — report would still answer \"no records\"")
	}
	// … so buildAbuseReport succeeds and surfaces the audited trail.
	rep, err := d.buildAbuseReport(ctx, attacker, 100, false)
	if err != nil {
		t.Fatalf("report must find the IP after exhaustion: %v", err)
	}
	sawExhausted := false
	for _, a := range rep.Actions {
		if a.Op == "recheck_exhausted" {
			sawExhausted = true
		}
	}
	if !sawExhausted {
		t.Errorf("audit trail missing the recheck_exhausted entry: %+v", rep.Actions)
	}

	// 3. Invariant untouched: observability only — never a ban.
	if enf.BanCount() != 0 {
		t.Fatalf("exhaustion path must never ban (anti-lockout), got %d bans", enf.BanCount())
	}

	// 4. Fresh event-driven evidence resets the budget: a new refusal
	// re-arms the re-check as before.
	feedBurst(ctx, d, attacker, 6)
	if d.sshRecheck.len() == 0 {
		t.Fatalf("fresh refusal after exhaustion did not re-arm the re-check")
	}
}

// TestSSHRecheckQueue_RequeueBudget pins the queue mechanics the fix
// depends on: requeue reports exhaustion, schedule resets the budget.
func TestSSHRecheckQueue_RequeueBudget(t *testing.T) {
	t.Parallel()
	q := &sshRecheckQueue{}
	ip := netip.MustParseAddr("203.0.113.46")

	if !q.requeue(ip, sshRecheckMaxAttempts-1, time.Now(), nil) {
		t.Fatalf("requeue below the budget must succeed")
	}
	q.due(time.Now().Add(time.Hour)) // drain
	if q.requeue(ip, sshRecheckMaxAttempts, time.Now(), nil) {
		t.Fatalf("requeue at the budget must report exhaustion")
	}
	// schedule = fresh event-driven evidence: budget resets to zero.
	if !q.schedule(ip, time.Now(), nil) {
		t.Fatalf("schedule after exhaustion must succeed")
	}
	items := q.due(time.Now().Add(time.Hour))
	if len(items) != 1 || items[0].attempts != 0 {
		t.Fatalf("schedule must reset the attempt budget, got %+v", items)
	}
}
