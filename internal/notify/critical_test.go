// SPDX-License-Identifier: AGPL-3.0-only

package notify_test

// Regression tests for issue #613: the per-channel rate limiter must never
// starve a critical, a dropped send must not consume the dedup window, and a
// suppressed send must be observable.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// TestDispatcher_CriticalSurvivesWarnBurst: five warnings fill a 5/min
// channel; the single critical that follows (the DEGRADED transition) must
// still be delivered.
func TestDispatcher_CriticalSurvivesWarnBurst(t *testing.T) {
	n := &stubNotifier{name: "phone"}
	d := notify.New([]sdk.Notifier{n}, 5, time.Hour, nil)
	for i := range 5 {
		_ = d.Send(context.Background(), makeMsg("warn", fmt.Sprintf("[ban] 203.0.113.%d — strike 1", i)))
	}
	before := n.sends.Load()
	_ = d.Send(context.Background(), makeMsg("critical", "enforcement DEGRADED: nftables down — bans may not be applied"))
	if got := n.sends.Load() - before; got != 1 {
		t.Fatalf("critical after a warn burst: delivered %d, want 1 (rate limiter must not be severity-blind)", got)
	}
}

// TestDispatcher_DroppedCriticalDoesNotConsumeDedup: a critical dropped by
// the limiter must not be recorded in the dedup window, so the same alert
// re-sent once the window frees up is delivered — not suppressed as a
// duplicate of a message nobody received.
func TestDispatcher_DroppedCriticalDoesNotConsumeDedup(t *testing.T) {
	n := &stubNotifier{name: "phone"}
	t0 := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	now := t0
	d := notify.NewWithClock([]sdk.Notifier{n}, 5, 10*time.Minute, nil, func() time.Time { return now })
	// Exhaust every quota a critical could use: the normal one and the
	// critical one (whatever its size), with distinct titles.
	for i := range 200 {
		_ = d.Send(context.Background(), makeMsg("critical", fmt.Sprintf("distinct critical %d", i)))
	}
	before := n.sends.Load()
	_ = d.Send(context.Background(), makeMsg("critical", "enforcement DEGRADED"))
	if n.sends.Load() != before {
		t.Skip("quota not exhausted after 200 criticals — nothing to test")
	}
	now = t0.Add(61 * time.Second) // quotas freed, dedup window (10 min) not elapsed
	_ = d.Send(context.Background(), makeMsg("critical", "enforcement DEGRADED"))
	if got := n.sends.Load() - before; got != 1 {
		t.Fatalf("re-sent critical after the quota freed: delivered %d, want 1 (a dropped send must not record the dedup key)", got)
	}
}

// slowNotifier holds each delivery for a while so concurrent sends of the
// same message overlap in flight.
type slowNotifier struct {
	sends atomic.Int32
	hold  time.Duration
}

func (s *slowNotifier) Name() string { return "slow" }
func (s *slowNotifier) Send(_ context.Context, _ sdk.Notification) error {
	s.sends.Add(1)
	time.Sleep(s.hold)
	return nil
}

// TestDispatcher_ConcurrentSameMessageDeliveredOnce (adversarial review of
// #613): the dedup check and the claim must be one atomic step, or two
// goroutines alerting the same enforcer failure both pass the check while
// the first is still in flight and the message goes out twice — and burns
// the critical quota twice.
func TestDispatcher_ConcurrentSameMessageDeliveredOnce(t *testing.T) {
	n := &slowNotifier{hold: 150 * time.Millisecond}
	d := notify.New([]sdk.Notifier{n}, 100, time.Hour, nil)
	msg := makeMsg(notify.SeverityCritical, "enforcement DEGRADED")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Send(context.Background(), msg)
		}()
	}
	wg.Wait()
	if got := n.sends.Load(); got != 1 {
		t.Fatalf("delivered %d times, want exactly 1", got)
	}
}

// TestDispatcher_FailedSendReleasesClaim: a send that no channel delivered
// gives the dedup window back, so the next attempt is not suppressed.
func TestDispatcher_FailedSendReleasesClaim(t *testing.T) {
	n := &stubNotifier{name: "n", retErr: errors.New("boom")}
	d := notify.New([]sdk.Notifier{n}, 100, time.Hour, nil)
	msg := makeMsg(notify.SeverityCritical, "enforcement DEGRADED")
	_ = d.Send(context.Background(), msg)
	n.retErr = nil
	_ = d.Send(context.Background(), msg)
	if got := n.sends.Load(); got != 2 {
		t.Fatalf("second attempt after a failed one was suppressed: sends=%d, want 2", got)
	}
}
