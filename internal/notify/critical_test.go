// SPDX-License-Identifier: AGPL-3.0-only

package notify_test

// Regression tests for issue #613: the per-channel rate limiter must never
// starve a critical, a dropped send must not consume the dedup window, and a
// suppressed send must be observable.

import (
	"context"
	"fmt"
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
