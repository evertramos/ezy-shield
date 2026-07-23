package daemon

// Tests for ban_ineffective delivery (ADR-0009 §4, issue #146): stream
// events per firing, systemic notification dedup across IPs, the distinct
// non-deduplicated pre-permanent alert, and no raw log data in payloads.

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func diag(ip string, strike int) decision.BanIneffectiveDiag {
	return decision.BanIneffectiveDiag{
		IP: netip.MustParseAddr(ip), Strike: strike, LadderLen: 5,
		NextRungs: "7d, permanent", EventsAfterGrace: 4, TotalSuppressed: 12, GraceSeconds: 90,
	}
}

// newDiagDaemon builds a minimal daemon with a fake notifier and a tight
// dedup window so windows can be crossed deterministically in-test.
func newDiagDaemon(t *testing.T, window time.Duration) (*Daemon, *fakeNotifier) {
	t.Helper()
	notif := &fakeNotifier{}
	d := &Daemon{
		notifier:   notify.New([]sdk.Notifier{notif}, 100, 0, nil),
		events:     newEventBus(),
		ineffDedup: ineffDedup{window: window},
	}
	return d, notif
}

func TestBanIneffective_NotificationDedupedSystemically(t *testing.T) {
	d, notif := newDiagDaemon(t, time.Hour) // window never elapses in-test
	ctx := context.Background()

	// Ten distinct IPs fire within the window — the classic "broken
	// enforcement fires for many IPs at once" scenario.
	for i := 0; i < 10; i++ {
		d.BanIneffective(ctx, diag("203.0.113."+itoa(i), 3))
	}
	if got := notif.Count(); got != 1 {
		t.Errorf("notifications = %d, want 1 (systemic dedup — one alert, not one per IP)", got)
	}
}

func TestBanIneffective_NewWindowNotifiesAgainWithCarry(t *testing.T) {
	d, notif := newDiagDaemon(t, 10*time.Millisecond)
	ctx := context.Background()

	d.BanIneffective(ctx, diag("203.0.113.1", 3)) // opens window, notifies
	d.BanIneffective(ctx, diag("203.0.113.2", 3)) // deduped
	d.BanIneffective(ctx, diag("203.0.113.3", 3)) // deduped
	time.Sleep(20 * time.Millisecond)             // window elapses
	d.BanIneffective(ctx, diag("203.0.113.4", 3)) // new window, notifies

	if got := notif.Count(); got != 2 {
		t.Fatalf("notifications = %d, want 2 (one per window)", got)
	}
	// The second alert must mention the aggregated firings from window 1.
	last := notif.msgs[len(notif.msgs)-1]
	if !strings.Contains(last.Body, "aggregated") {
		t.Errorf("second alert body missing the carried-over count:\n%s", last.Body)
	}
}

func TestBanIneffective_StreamEventPerFiring(t *testing.T) {
	d, _ := newDiagDaemon(t, time.Hour)
	ctx := context.Background()

	// Subscribe to the event bus and collect events.
	sub := d.events.subscribe()
	defer d.events.unsubscribe(sub)

	go func() {
		for i := 0; i < 3; i++ {
			d.BanIneffective(ctx, diag("203.0.113."+itoa(i), 3))
		}
	}()

	got := 0
	timeout := time.After(2 * time.Second)
	for got < 3 {
		select {
		case ev := <-sub:
			if ev.Kind != "ban_ineffective" {
				t.Errorf("event kind = %q, want ban_ineffective", ev.Kind)
			}
			got++
		case <-timeout:
			t.Fatalf("only %d of 3 stream events received", got)
		}
	}
}

func TestBanIneffectivePermanent_NeverDeduped(t *testing.T) {
	d, notif := newDiagDaemon(t, time.Hour)
	ctx := context.Background()

	// Two DIFFERENT IPs: unlike BanIneffective, the pre-permanent alert has
	// no systemic dedup, so each distinct promotion notifies. (Two promotions
	// of the SAME IP cannot happen in production — an IP goes permanent once
	// — and the shared Dispatcher content-dedups identical messages anyway;
	// the invariant that matters is that distinct promotions are never
	// swallowed.)
	d.BanIneffectivePermanent(ctx, netip.MustParseAddr("203.0.113.7"), 5)
	d.BanIneffectivePermanent(ctx, netip.MustParseAddr("203.0.113.8"), 5)

	if got := notif.Count(); got != 2 {
		t.Errorf("pre-permanent notifications = %d, want 2 (distinct promotions never deduped — must not pass silently)", got)
	}
	for _, m := range notif.msgs {
		if m.Severity != "critical" {
			t.Errorf("severity = %q, want critical", m.Severity)
		}
	}
}

func TestBanIneffective_NoRawLogDataInPayload(t *testing.T) {
	d, notif := newDiagDaemon(t, time.Hour)
	// The diag carries only engine-derived fields; a firing's notification
	// must contain the IP/strike/counts and nothing resembling a log line.
	d.BanIneffective(context.Background(), diag("203.0.113.9", 2))
	if notif.Count() != 1 {
		t.Fatal("expected one notification")
	}
	body := notif.msgs[0].Body
	for _, want := range []string{"203.0.113.9", "systemic", "enforcement"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
	// Sanity: the payload is built from BanIneffectiveDiag only — there is
	// no code path that could smuggle a raw log line in (compile-time
	// guarantee), and the body carries no newline-delimited log markers.
	if strings.Contains(body, "\t") {
		t.Errorf("body contains a tab — possible raw log leakage:\n%s", body)
	}
}

func TestBanIneffective_NilNotifierIsSafe(t *testing.T) {
	d := &Daemon{events: newEventBus()} // no notifier
	// Must not panic; stream event still attempted (no subscribers → no-op).
	d.BanIneffective(context.Background(), diag("203.0.113.1", 3))
	d.BanIneffectivePermanent(context.Background(), netip.MustParseAddr("203.0.113.1"), 5)
}

// itoa is a tiny local helper (avoids importing strconv for one use).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

var _ decision.Diagnostics = (*Daemon)(nil) // compile-time interface check
var _ = sdk.Notification{}                  // keep sdk import when trimmed
