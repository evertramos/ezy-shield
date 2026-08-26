package daemon

// Socket-API tests for the feeds verbs (issue #196), same pattern as the
// other socket-command tests.

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestSocketFeedsStatus_NoFeedsConfigured(t *testing.T) {
	d := newTestDaemonForSocket(t, false)
	resp := callSocket(t, d, SocketRequest{Verb: "feeds_status"})
	if resp.OK || !strings.Contains(resp.Error, "no reputation feeds configured") {
		t.Fatalf("want not-configured error, got %+v", resp)
	}
}

func TestSocketFeedsRefreshAndStatus(t *testing.T) {
	d := newTestDaemonForSocket(t, false)
	// Scripted refresh: pretends run.go's injected fetch for two feeds.
	d.feedRefresh = func(ctx context.Context, name string, report func(FeedUpdate)) (int, error) {
		feedsAll := []FeedUpdate{
			{Name: "drop", Action: "observe", Interval: 12 * time.Hour,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
			{Name: "abuse", Action: "observe", Interval: 24 * time.Hour,
				Prefixes: []netip.Prefix{
					netip.MustParsePrefix("203.0.113.5/32"),
					netip.MustParsePrefix("203.0.113.6/32"),
				}},
		}
		n := 0
		for _, u := range feedsAll {
			if name != "" && u.Name != name {
				continue
			}
			report(u)
			n++
		}
		return n, nil
	}

	// Refresh all.
	resp := callSocket(t, d, SocketRequest{Verb: "feeds_refresh"})
	if !resp.OK {
		t.Fatalf("feeds_refresh: %s", resp.Error)
	}
	var rd FeedsRefreshData
	if err := json.Unmarshal(resp.Data, &rd); err != nil || rd.Refreshed != 2 {
		t.Fatalf("refresh data = %+v (%v), want refreshed=2", rd, err)
	}

	// Status now lists both feeds, sorted by name, with entries counted.
	resp = callSocket(t, d, SocketRequest{Verb: "feeds_status"})
	if !resp.OK {
		t.Fatalf("feeds_status: %s", resp.Error)
	}
	var entries []FeedStatusEntry
	if err := json.Unmarshal(resp.Data, &entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 2 || entries[0].Name != "abuse" || entries[1].Name != "drop" {
		t.Fatalf("entries = %+v, want [abuse drop]", entries)
	}
	if entries[0].Entries != 2 || entries[1].Entries != 1 {
		t.Errorf("entry counts = %d/%d, want 2/1", entries[0].Entries, entries[1].Entries)
	}
	if entries[0].NextRefresh.IsZero() || entries[0].LastRefresh.IsZero() {
		t.Errorf("refresh timestamps not populated: %+v", entries[0])
	}

	// Refresh one by name.
	resp = callSocket(t, d, SocketRequest{Verb: "feeds_refresh", Name: "drop"})
	if !resp.OK {
		t.Fatalf("named feeds_refresh: %s", resp.Error)
	}
	if err := json.Unmarshal(resp.Data, &rd); err != nil || rd.Refreshed != 1 {
		t.Fatalf("named refresh data = %+v, want refreshed=1", rd)
	}
}

func TestSocketFeedsRefresh_UnknownName(t *testing.T) {
	d := newTestDaemonForSocket(t, false)
	d.feedRefresh = func(_ context.Context, name string, _ func(FeedUpdate)) (int, error) {
		if name == "nope" {
			return 0, errTestNoFeed
		}
		return 0, nil
	}
	resp := callSocket(t, d, SocketRequest{Verb: "feeds_refresh", Name: "nope"})
	if resp.OK || !strings.Contains(resp.Error, "no configured feed") {
		t.Fatalf("want unknown-feed error, got %+v", resp)
	}
}

var errTestNoFeed = errNoFeedNamed("nope")

type errNoFeedNamed string

func (e errNoFeedNamed) Error() string { return "no configured feed named \"" + string(e) + "\"" }
