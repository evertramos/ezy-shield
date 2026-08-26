// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Tests for reputation-feed enforcement (issue #195).

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// fakeFeedSyncer records SyncFeeds calls.
type fakeFeedSyncer struct {
	mu    sync.Mutex
	calls [][]enforce.FeedElement
}

func (f *fakeFeedSyncer) SyncFeeds(_ context.Context, elems []enforce.FeedElement) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]enforce.FeedElement(nil), elems...)
	f.calls = append(f.calls, cp)
	return nil
}

func (f *fakeFeedSyncer) last(t *testing.T) []enforce.FeedElement {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("SyncFeeds was never called")
	}
	return f.calls[len(f.calls)-1]
}

func mustPfx(t *testing.T, s string) netip.Prefix {
	t.Helper()
	return netip.MustParsePrefix(s)
}

// newFeedTestDaemon builds an armed daemon with an allowlist covering
// 198.51.100.0/24, a scripted SSH peer, and a fake feed syncer.
func newFeedTestDaemon(t *testing.T, armed bool) (*Daemon, *fakeFeedSyncer) {
	t.Helper()
	d := newTestDaemonForSocket(t, armed)
	fs := &fakeFeedSyncer{}
	d.feedSyncer = fs
	d.staticAllowlist = []netip.Prefix{mustPfx(t, "198.51.100.0/24")}
	d.feedSSHPeersFn = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("203.0.113.77")}
	}
	return d, fs
}

// TestHandleFeedUpdate_GuardrailsWin is the MANDATORY allowlist-wins test:
// a feed carrying an allowlisted IP and the current SSH peer must have both
// dropped before anything reaches the enforcer.
func TestHandleFeedUpdate_GuardrailsWin(t *testing.T) {
	d, fs := newFeedTestDaemon(t, true)
	ctx := context.Background()

	d.handleFeedUpdate(ctx, FeedUpdate{
		Name:   "poisoned",
		Action: "block",
		TTL:    time.Hour,
		Prefixes: []netip.Prefix{
			mustPfx(t, "198.51.100.7/32"), // allowlisted → dropped
			mustPfx(t, "198.51.100.0/25"), // overlaps allowlist → dropped
			mustPfx(t, "203.0.113.77/32"), // the active SSH peer → dropped
			mustPfx(t, "203.0.113.0/24"),  // CONTAINS the SSH peer → dropped
			mustPfx(t, "192.0.2.66/32"),   // clean → applied
		},
	})

	got := fs.last(t)
	if len(got) != 1 || got[0].IP != "192.0.2.66" {
		t.Fatalf("SyncFeeds got %v, want only 192.0.2.66", got)
	}
	if got[0].TTLSeconds != 3600 {
		t.Errorf("TTLSeconds = %d, want 3600 (the feed ttl)", got[0].TTLSeconds)
	}

	// One audit summary row — not one per IP — with the skip count.
	entries, err := d.store.ListAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	var feedRows []string
	for _, e := range entries {
		if e.Op == "feed_refresh" {
			feedRows = append(feedRows, e.Reason)
		}
	}
	if len(feedRows) != 1 {
		t.Fatalf("feed_refresh rows = %d, want exactly 1 summary row (%v)", len(feedRows), feedRows)
	}
	for _, want := range []string{"poisoned", "entries=1", "skipped_by_guardrails=4"} {
		if !strings.Contains(feedRows[0], want) {
			t.Errorf("audit row missing %q: %s", want, feedRows[0])
		}
	}
}

// TestHandleFeedUpdate_DryRunWritesNothing pins armed:false semantics.
func TestHandleFeedUpdate_DryRunWritesNothing(t *testing.T) {
	d, fs := newFeedTestDaemon(t, false)
	d.handleFeedUpdate(context.Background(), FeedUpdate{
		Name:     "drop",
		Action:   "block",
		TTL:      time.Hour,
		Prefixes: []netip.Prefix{mustPfx(t, "192.0.2.10/32")},
	})
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.calls) != 0 {
		t.Fatalf("dry-run must not touch the firewall, got %d SyncFeeds calls", len(fs.calls))
	}
}

// TestHandleFeedUpdate_ReconcileAddRemove pins the full-replace semantics:
// a refresh with fewer entries removes the stale ones from the desired set.
func TestHandleFeedUpdate_ReconcileAddRemove(t *testing.T) {
	d, fs := newFeedTestDaemon(t, true)
	ctx := context.Background()

	d.handleFeedUpdate(ctx, FeedUpdate{
		Name: "drop", Action: "block", TTL: time.Hour,
		Prefixes: []netip.Prefix{mustPfx(t, "192.0.2.1/32"), mustPfx(t, "192.0.2.2/32")},
	})
	if got := fs.last(t); len(got) != 2 {
		t.Fatalf("first sync = %v, want 2 entries", got)
	}
	d.handleFeedUpdate(ctx, FeedUpdate{
		Name: "drop", Action: "block", TTL: time.Hour,
		Prefixes: []netip.Prefix{mustPfx(t, "192.0.2.2/32")},
	})
	got := fs.last(t)
	if len(got) != 1 || got[0].IP != "192.0.2.2" {
		t.Fatalf("second sync = %v, want only 192.0.2.2 (stale removed)", got)
	}

	// Two feeds combine into one desired set.
	d.handleFeedUpdate(ctx, FeedUpdate{
		Name: "other", Action: "block", TTL: 30 * time.Minute,
		Prefixes: []netip.Prefix{mustPfx(t, "203.0.113.9/32")},
	})
	if got := fs.last(t); len(got) != 2 {
		t.Fatalf("combined sync = %v, want entries from both feeds", got)
	}
}

// TestHandleFeedUpdate_NoStrikesNoBans pins that feed entries never touch
// the strike/ban store — they are invisible to `ezyshield list`.
func TestHandleFeedUpdate_NoStrikesNoBans(t *testing.T) {
	d, _ := newFeedTestDaemon(t, true)
	ctx := context.Background()
	d.handleFeedUpdate(ctx, FeedUpdate{
		Name: "drop", Action: "block", TTL: time.Hour,
		Prefixes: []netip.Prefix{mustPfx(t, "192.0.2.44/32")},
	})
	bans, err := d.store.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 0 {
		t.Fatalf("feed entries created bans: %v", bans)
	}
}

// TestFeedReputation_ObserveBoost pins the observe path: entries flag the
// reputation store, and rule verdicts for a flagged IP get the score boost
// with the feed named in the reason.
func TestFeedReputation_ObserveBoost(t *testing.T) {
	d, fs := newFeedTestDaemon(t, true)
	ctx := context.Background()
	attacker := netip.MustParseAddr("192.0.2.99")

	d.handleFeedUpdate(ctx, FeedUpdate{
		Name:   "rep",
		Action: "observe",
		Prefixes: []netip.Prefix{
			mustPfx(t, "192.0.2.99/32"),
			mustPfx(t, "2001:db8:bad::/48"), // wide prefix path
		},
	})
	fs.mu.Lock()
	syncCalls := len(fs.calls)
	fs.mu.Unlock()
	if syncCalls != 0 {
		t.Fatalf("observe feed must never reach the firewall, got %d SyncFeeds calls", syncCalls)
	}

	if feed, ok := d.feedRep.Lookup(attacker); !ok || feed != "rep" {
		t.Fatalf("Lookup(%s) = %q,%v; want rep,true", attacker, feed, ok)
	}
	if feed, ok := d.feedRep.Lookup(netip.MustParseAddr("2001:db8:bad::1")); !ok || feed != "rep" {
		t.Fatalf("wide-prefix lookup failed: %q,%v", feed, ok)
	}
	if _, ok := d.feedRep.Lookup(netip.MustParseAddr("203.0.113.1")); ok {
		t.Fatal("unflagged IP must not match")
	}

	// Local events + reputation → boosted verdicts. Without local events
	// the feed alone produces nothing.
	if v := d.evaluateRules(ctx, attacker, false); len(v) != 0 {
		t.Fatalf("feed alone produced verdicts: %+v", v)
	}
	now := time.Now()
	for i := 0; i < 10; i++ {
		d.agg.Add(sdk.Event{
			Time:     now,
			SourceIP: attacker,
			Kind:     "ssh_fail",
		})
	}
	verdicts := d.evaluateRules(ctx, attacker, false)
	if len(verdicts) == 0 {
		t.Fatal("expected rule verdicts after 10 ssh_auth_fail events")
	}
	boosted := false
	for _, v := range verdicts {
		if strings.Contains(v.Reason, "[reputation:rep]") {
			boosted = true
			if v.Score > 100 {
				t.Errorf("score above 100: %d", v.Score)
			}
		}
	}
	if !boosted {
		t.Fatalf("no verdict carries the reputation boost: %+v", verdicts)
	}
}
