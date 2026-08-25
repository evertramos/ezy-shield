package daemon

// Tests for the notify_only suppression window (issue #421).

import (
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func notifyOnlyAction(ip string, rule string) sdk.Action {
	addr := netip.MustParseAddr(ip)
	return sdk.Action{
		IP:     addr,
		Op:     "notify_only",
		Reason: "score=60 category=" + rule + " source=rules",
		Verdicts: []sdk.Verdict{{
			IP: addr, Score: 60, Category: rule, Reason: "probe burst", Source: "rules",
		}},
	}
}

func suppressorWithClock(window time.Duration) (*notifySuppressor, func(d time.Duration)) {
	s := newNotifySuppressor(window)
	base := time.Now()
	var off atomic.Int64
	s.nowFn = func() time.Time { return base.Add(time.Duration(off.Load())) }
	return s, func(d time.Duration) { off.Add(int64(d)) }
}

// TestNotifySuppress_BurstFoldsIntoOneSummary: first event notifies, repeats
// within the window are suppressed, and the closed window yields exactly one
// summary carrying the fold count.
func TestNotifySuppress_BurstFoldsIntoOneSummary(t *testing.T) {
	t.Parallel()
	s, advance := suppressorWithClock(time.Hour)
	a := notifyOnlyAction("192.0.2.60", "http_scanner_400")

	send, summary := s.admit(a)
	if !send || summary != nil {
		t.Fatalf("first occurrence must notify immediately (send=%v summary=%v)", send, summary)
	}
	for i := 0; i < 9; i++ {
		advance(time.Minute)
		if send, _ := s.admit(a); send {
			t.Fatalf("repeat %d within the window must be suppressed", i+1)
		}
	}

	advance(2 * time.Hour) // window closed
	msgs := s.flush()
	if len(msgs) != 1 {
		t.Fatalf("closed window must yield exactly 1 summary, got %d", len(msgs))
	}
	if !strings.Contains(msgs[0].Title, "9 repeats suppressed") {
		t.Errorf("summary must carry the fold count: %q", msgs[0].Title)
	}
	if !strings.Contains(msgs[0].Body, "192.0.2.60|http_scanner_400") {
		t.Errorf("summary must name the (IP, rule) stream: %q", msgs[0].Body)
	}
	if len(s.flush()) != 0 {
		t.Error("summary must fire once — second flush emitted again")
	}
}

// TestNotifySuppress_WindowExpiryNotifiesAgain: after the window closes, the
// next event for the same key notifies immediately and carries the previous
// window's summary alongside.
func TestNotifySuppress_WindowExpiryNotifiesAgain(t *testing.T) {
	t.Parallel()
	s, advance := suppressorWithClock(time.Hour)
	a := notifyOnlyAction("192.0.2.61", "http_scanner_503")

	if send, _ := s.admit(a); !send {
		t.Fatal("first occurrence must notify")
	}
	advance(10 * time.Minute)
	if send, _ := s.admit(a); send {
		t.Fatal("repeat within window must be suppressed")
	}

	advance(2 * time.Hour)
	send, summary := s.admit(a)
	if !send {
		t.Fatal("first event of a NEW window must notify immediately")
	}
	if summary == nil || !strings.Contains(summary.Title, "1 repeats suppressed") {
		t.Fatalf("expired window with suppressed repeats must yield its summary alongside, got %v", summary)
	}
}

// TestNotifySuppress_DistinctStreamsAreIndependent: different IPs and
// different rules never share a window.
func TestNotifySuppress_DistinctStreamsAreIndependent(t *testing.T) {
	t.Parallel()
	s, _ := suppressorWithClock(time.Hour)

	if send, _ := s.admit(notifyOnlyAction("192.0.2.62", "http_scanner_400")); !send {
		t.Fatal("stream 1 first event must notify")
	}
	if send, _ := s.admit(notifyOnlyAction("192.0.2.63", "http_scanner_400")); !send {
		t.Fatal("different IP, same rule: must notify (independent stream)")
	}
	if send, _ := s.admit(notifyOnlyAction("192.0.2.62", "http_scanner_503")); !send {
		t.Fatal("same IP, different rule: must notify (independent stream)")
	}
}

// TestNotifySuppress_CleanWindowYieldsNoSummary: a window with zero
// suppressed repeats closes silently.
func TestNotifySuppress_CleanWindowYieldsNoSummary(t *testing.T) {
	t.Parallel()
	s, advance := suppressorWithClock(time.Hour)
	if send, _ := s.admit(notifyOnlyAction("192.0.2.64", "http_scanner_400")); !send {
		t.Fatal("first occurrence must notify")
	}
	advance(2 * time.Hour)
	if msgs := s.flush(); len(msgs) != 0 {
		t.Fatalf("no repeats were suppressed — no summary expected, got %d", len(msgs))
	}
}
