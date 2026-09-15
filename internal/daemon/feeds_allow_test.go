// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Issue #608, feeds half: the runtime allowlist guards reputation feeds like
// the static one, and `disable --all` empties the feed sets — otherwise an
// allowed (or panic-buttoned) address stays dropped by @feeds for the feed TTL.

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestHandleFeedUpdate_RuntimeAllowlistGuards(t *testing.T) {
	d, fs := newFeedTestDaemon(t, true)
	ctx := context.Background()
	if resp := d.handleAllow(ctx, SocketRequest{Verb: "allow", IP: "192.0.2.200"}); !resp.OK {
		t.Fatalf("allow: %s", resp.Error)
	}
	d.handleFeedUpdate(ctx, FeedUpdate{
		Name: "feed", Action: "block", TTL: time.Hour,
		Prefixes: []netip.Prefix{
			mustPfx(t, "192.0.2.200/32"), // runtime-allowed → must be skipped
			mustPfx(t, "192.0.2.128/25"), // covers it → must be skipped
			mustPfx(t, "192.0.2.66/32"),  // clean → applied
		},
	})
	last := fs.last(t)
	if len(last) != 1 || last[0].IP != "192.0.2.66" {
		t.Fatalf("feed elements = %+v, want only 192.0.2.66", last)
	}
	d.feedMu.Lock()
	skipped := d.feedStatus["feed"].Skipped
	d.feedMu.Unlock()
	if skipped != 2 {
		t.Fatalf("skipped = %d, want 2 (the runtime-allowed entry and the prefix covering it)", skipped)
	}
}

func TestDisableAll_ClearsFeedSets(t *testing.T) {
	d, fs := newFeedTestDaemon(t, true)
	ctx := context.Background()
	d.handleFeedUpdate(ctx, FeedUpdate{
		Name: "feed", Action: "block", TTL: time.Hour,
		Prefixes: []netip.Prefix{mustPfx(t, "192.0.2.66/32")},
	})
	if got := fs.last(t); len(got) != 1 {
		t.Fatalf("precondition: feed not applied: %+v", got)
	}
	if resp := d.handleDisableAll(ctx); !resp.OK {
		t.Fatalf("disable --all: %s", resp.Error)
	}
	if got := fs.last(t); len(got) != 0 {
		t.Fatalf("after disable --all the feed sets still hold %+v, want empty", got)
	}
}
