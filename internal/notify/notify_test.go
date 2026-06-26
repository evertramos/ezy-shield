package notify_test

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// stubNotifier records every Send call and optionally returns an error.
type stubNotifier struct {
	name   string
	sends  atomic.Int32
	retErr error
}

func (s *stubNotifier) Name() string { return s.name }
func (s *stubNotifier) Send(_ context.Context, _ sdk.Notification) error {
	s.sends.Add(1)
	return s.retErr
}

func makeMsg(sev, title string) sdk.Notification {
	return sdk.Notification{Severity: sev, Title: title}
}

func mustParseAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(fmt.Sprintf("mustParseAddr(%q): %v", s, err))
	}
	return a
}

// ── Dispatcher basic fan-out ───────────────────────────────────────────────────

func TestDispatcher_FansOutToAllChannels(t *testing.T) {
	a := &stubNotifier{name: "a"}
	b := &stubNotifier{name: "b"}
	d := notify.New([]sdk.Notifier{a, b}, 100, time.Hour, nil)

	if err := d.Send(context.Background(), makeMsg("info", "test")); err != nil {
		t.Fatal(err)
	}
	if a.sends.Load() != 1 {
		t.Errorf("notifier a: expected 1 send, got %d", a.sends.Load())
	}
	if b.sends.Load() != 1 {
		t.Errorf("notifier b: expected 1 send, got %d", b.sends.Load())
	}
}

func TestDispatcher_RegisterAddsChannel(t *testing.T) {
	d := notify.New(nil, 100, time.Hour, nil)
	n := &stubNotifier{name: "late"}
	d.Register(n, 100, nil)

	if err := d.Send(context.Background(), makeMsg("info", "hi")); err != nil {
		t.Fatal(err)
	}
	if n.sends.Load() != 1 {
		t.Errorf("expected 1 send after Register, got %d", n.sends.Load())
	}
}

// ── Severity routing ──────────────────────────────────────────────────────────

func TestDispatcher_SeverityRouting(t *testing.T) {
	warnOnly := &stubNotifier{name: "warnOnly"}
	all := &stubNotifier{name: "all"}
	sev := map[string][]string{"warnOnly": {"warn", "critical"}}
	d := notify.New([]sdk.Notifier{warnOnly, all}, 100, time.Hour, sev)

	_ = d.Send(context.Background(), makeMsg("info", "low"))
	if warnOnly.sends.Load() != 0 {
		t.Errorf("warnOnly should not receive info notifications")
	}
	if all.sends.Load() != 1 {
		t.Errorf("all should receive info notifications")
	}

	_ = d.Send(context.Background(), makeMsg("warn", "med"))
	if warnOnly.sends.Load() != 1 {
		t.Errorf("warnOnly should receive warn notifications")
	}
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

func TestDispatcher_RateLimitDropsExcess(t *testing.T) {
	n := &stubNotifier{name: "rl"}
	// maxPerMinute=2 so the third send should be dropped.
	d := notify.New([]sdk.Notifier{n}, 2, time.Hour, nil)

	for i := range 5 {
		msg := makeMsg("info", fmt.Sprintf("msg%d", i))
		_ = d.Send(context.Background(), msg)
	}
	if got := n.sends.Load(); got > 2 {
		t.Errorf("expected at most 2 sends under rate limit of 2, got %d", got)
	}
}

// ── Dedup window ──────────────────────────────────────────────────────────────

func TestDispatcher_DedupSuppressesRepeat(t *testing.T) {
	n := &stubNotifier{name: "dedup"}
	d := notify.New([]sdk.Notifier{n}, 100, 5*time.Minute, nil)

	msg := makeMsg("warn", "same")
	_ = d.Send(context.Background(), msg)
	_ = d.Send(context.Background(), msg) // duplicate within window
	_ = d.Send(context.Background(), msg)

	if got := n.sends.Load(); got != 1 {
		t.Errorf("expected 1 send (dedup suppressed duplicates), got %d", got)
	}
}

func TestDispatcher_DedupAllowsAfterWindowExpires(t *testing.T) {
	n := &stubNotifier{name: "dedupExpiry"}
	// Inject a controllable clock: first call returns t0, subsequent calls advance.
	var callCount int
	t0 := time.Now()
	clk := func() time.Time {
		callCount++
		// After the first "record" call, advance by 20ms.
		if callCount > 1 {
			return t0.Add(20 * time.Millisecond)
		}
		return t0
	}
	d := notify.NewWithClock([]sdk.Notifier{n}, 100, 10*time.Millisecond, nil, clk)

	msg := makeMsg("warn", "expiry")
	_ = d.Send(context.Background(), msg) // recorded at t0
	_ = d.Send(context.Background(), msg) // clock now returns t0+20ms > window → allowed

	if got := n.sends.Load(); got != 2 {
		t.Errorf("expected 2 sends after dedup window expired, got %d", got)
	}
}

func TestDispatcher_DedupKeyPerIP(t *testing.T) {
	n := &stubNotifier{name: "ipkey"}
	d := notify.New([]sdk.Notifier{n}, 100, time.Hour, nil)

	ip1 := mustParseAddr("1.2.3.4")
	ip2 := mustParseAddr("5.6.7.8")
	reason := "brute-force"

	_ = d.Send(context.Background(), sdk.Notification{
		Severity: "warn", Title: "ban",
		Action: &sdk.Action{IP: ip1, Reason: reason},
	})
	_ = d.Send(context.Background(), sdk.Notification{
		Severity: "warn", Title: "ban",
		Action: &sdk.Action{IP: ip2, Reason: reason},
	})

	if got := n.sends.Load(); got != 2 {
		t.Errorf("expected 2 sends for different IPs, got %d", got)
	}
}

func TestDispatcher_DedupSuppressesSameIPAndReason(t *testing.T) {
	n := &stubNotifier{name: "ipreasonkey"}
	d := notify.New([]sdk.Notifier{n}, 100, time.Hour, nil)

	ip := mustParseAddr("1.2.3.4")
	_ = d.Send(context.Background(), sdk.Notification{
		Severity: "warn", Title: "ban",
		Action: &sdk.Action{IP: ip, Reason: "brute-force"},
	})
	// Same IP+reason within window → suppressed even with different severity/title.
	_ = d.Send(context.Background(), sdk.Notification{
		Severity: "critical", Title: "repeat",
		Action: &sdk.Action{IP: ip, Reason: "brute-force"},
	})

	if got := n.sends.Load(); got != 1 {
		t.Errorf("expected 1 send (same IP+reason deduped), got %d", got)
	}
}

// ── Send error propagation ────────────────────────────────────────────────────

func TestDispatcher_ReturnsErrorFromNotifier(t *testing.T) {
	n := &stubNotifier{name: "err", retErr: fmt.Errorf("boom")}
	d := notify.New([]sdk.Notifier{n}, 100, time.Hour, nil)

	err := d.Send(context.Background(), makeMsg("critical", "oops"))
	if err == nil {
		t.Fatal("expected error from failing notifier, got nil")
	}
}
