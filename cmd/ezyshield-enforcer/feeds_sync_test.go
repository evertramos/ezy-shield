// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the feeds_sync verb (issue #195): atomic desired-state replace
// of the reputation-feed sets.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/nftnames"
)

func TestDispatch_FeedsSync_AtomicScript(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	resp := doRPC(t, srv.sockPath(), enforce.Request{
		Verb: "feeds_sync",
		Elements: []enforce.FeedElement{
			{IP: "192.0.2.0/24", TTLSeconds: 86400},
			{IP: "198.51.100.7", TTLSeconds: 3600},
			{IP: "2001:db8::/48", TTLSeconds: 86400},
		},
	})
	if !resp.OK {
		t.Fatalf("feeds_sync failed: %s", resp.Error)
	}
	if len(mock.scripts) != 1 {
		t.Fatalf("scripts = %d, want exactly ONE atomic script", len(mock.scripts))
	}
	script := mock.scripts[0]
	for _, want := range []string{
		"flush set inet ezyshield blocked_feeds\n",
		"flush set inet ezyshield blocked_feeds6\n",
		"192.0.2.0/24 timeout 86400s",
		"198.51.100.7 timeout 3600s",
		"2001:db8::/48 timeout 86400s",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q:\n%s", want, script)
		}
	}
	// v4 entries land in blocked_feeds, v6 in blocked_feeds6 — never the
	// ban sets.
	if strings.Contains(script, " blocked {") || strings.Contains(script, " blocked6 {") {
		t.Errorf("feed entries leaked into the ban sets:\n%s", script)
	}
	if !strings.Contains(script, "add element inet ezyshield blocked_feeds {") ||
		!strings.Contains(script, "add element inet ezyshield blocked_feeds6 {") {
		t.Errorf("expected adds into blocked_feeds/blocked_feeds6:\n%s", script)
	}
	// Flush must precede every add (full replace, not accumulate).
	if strings.Index(script, "flush set") > strings.Index(script, "add element") {
		t.Errorf("flush does not precede adds:\n%s", script)
	}
}

func TestDispatch_FeedsSync_EmptyClearsSets(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "feeds_sync"})
	if !resp.OK {
		t.Fatalf("empty feeds_sync failed: %s", resp.Error)
	}
	script := mock.scripts[len(mock.scripts)-1]
	if !strings.Contains(script, "flush set inet ezyshield blocked_feeds") {
		t.Errorf("empty sync must still flush:\n%s", script)
	}
	if strings.Contains(script, "add element") {
		t.Errorf("empty sync must not add anything:\n%s", script)
	}
}

func TestDispatch_FeedsSync_Validation(t *testing.T) {
	cases := []struct {
		name    string
		elems   []enforce.FeedElement
		wantErr string
	}{
		{
			name:    "invalid IP",
			elems:   []enforce.FeedElement{{IP: "not-an-ip; drop table", TTLSeconds: 60}},
			wantErr: "not a valid",
		},
		{
			name:    "zero ttl",
			elems:   []enforce.FeedElement{{IP: "192.0.2.1", TTLSeconds: 0}},
			wantErr: "ttl must be positive",
		},
		{
			name:    "negative ttl",
			elems:   []enforce.FeedElement{{IP: "192.0.2.1", TTLSeconds: -5}},
			wantErr: "ttl must be positive",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockNftCalls{}
			srv := startTestServer(t, mock)
			resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "feeds_sync", Elements: tc.elems})
			if resp.OK || !strings.Contains(resp.Error, tc.wantErr) {
				t.Fatalf("want error containing %q, got ok=%v err=%q", tc.wantErr, resp.OK, resp.Error)
			}
			if len(mock.scripts) != 0 {
				t.Errorf("invalid request reached nft: %v", mock.scripts)
			}
		})
	}
}

func TestDispatch_FeedsSync_OverCapRejected(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	elems := make([]enforce.FeedElement, enforce.MaxFeedElements+1)
	for i := range elems {
		elems[i] = enforce.FeedElement{
			IP:         fmt.Sprintf("192.0.2.%d", i%256),
			TTLSeconds: 60,
		}
	}
	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "feeds_sync", Elements: elems})
	if resp.OK || !strings.Contains(resp.Error, "cap") {
		t.Fatalf("over-cap request must be rejected, got ok=%v err=%q", resp.OK, resp.Error)
	}
	if len(mock.scripts) != 0 {
		t.Errorf("over-cap request reached nft")
	}
}

func TestDispatch_Caps_AdvertisesFeedsSync(t *testing.T) {
	srv := startTestServer(t, &mockNftCalls{})
	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "caps"})
	if !resp.OK {
		t.Fatalf("caps failed: %s", resp.Error)
	}
	found := false
	for _, f := range resp.Features {
		if f == enforce.FeatureFeedsSync {
			found = true
		}
	}
	if !found {
		t.Errorf("caps features = %v, want %s advertised", resp.Features, enforce.FeatureFeedsSync)
	}
}

func TestInitTable_CreatesFeedSetsAndRules(t *testing.T) {
	mock := &mockNftCalls{}
	names, err := nftnames.Resolve("", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := initTable(t.Context(), mock.runner(), names); err != nil {
		t.Fatalf("initTable: %v", err)
	}
	script := mock.scripts[0]
	for _, want := range []string{
		"add set inet ezyshield blocked_feeds { type ipv4_addr ; flags interval,timeout ; auto-merge ; }",
		"add set inet ezyshield blocked_feeds6 { type ipv6_addr ; flags interval,timeout ; auto-merge ; }",
		"add rule inet ezyshield prerouting ip saddr @blocked_feeds drop",
		"add rule inet ezyshield prerouting ip6 saddr @blocked_feeds6 drop",
		"add rule inet ezyshield input ip saddr @blocked_feeds drop",
		"add rule inet ezyshield forward ip saddr @blocked_feeds drop",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("initTable script missing %q", want)
		}
	}
	// Anti-lockout: the allowlist accept rules must precede every feed drop.
	if strings.Index(script, "@allowed accept") > strings.Index(script, "@blocked_feeds drop") {
		t.Errorf("allowlist accept does not precede feed drops:\n%s", script)
	}
}
