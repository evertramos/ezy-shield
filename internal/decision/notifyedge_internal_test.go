// SPDX-License-Identifier: AGPL-3.0-only

package decision

// In-package tests for the notify_only edge map's bound (issue #649): the
// behaviour (one audit row per rising edge) is pinned from decision_test in
// notifyedge_test.go; these look at the map itself, which the public API
// deliberately does not expose.

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// TestNotifyEdge_MapIsBounded: more distinct IPs than notifyEdgeMaxEntries
// inside one window never grow the map past the cap; expired edges are
// swept first, and when none has expired one arbitrary edge is dropped
// (O(1); any dropped edge costs at most one extra audit row).
func TestNotifyEdge_MapIsBounded(t *testing.T) {
	e := &Engine{}
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)

	// 2001:db8::/32 (RFC 3849) gives more than enough distinct addresses.
	addr := func(i uint32) netip.Addr {
		var b [16]byte
		b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
		binary.BigEndian.PutUint32(b[12:], i)
		return netip.AddrFrom16(b)
	}

	for i := range uint32(notifyEdgeMaxEntries + 500) {
		// Every edge is still inside the window, so the cap forces oldest-drop.
		if !e.notifyEdgeRising(addr(i), "rule/x", now.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatalf("fresh IP #%d reported as repeat", i)
		}
		if n := len(e.notifyEdges); n > notifyEdgeMaxEntries {
			t.Fatalf("after %d inserts map has %d entries, cap %d", i+1, n, notifyEdgeMaxEntries)
		}
	}
	if _, ok := e.notifyEdges[addr(notifyEdgeMaxEntries+499)]; !ok {
		t.Fatalf("the edge just inserted was not kept")
	}

	// Past the window every entry is expired: one insert sweeps them all.
	later := now.Add(notifyEdgeWindow + time.Hour)
	if !e.notifyEdgeRising(netip.MustParseAddr("192.0.2.1"), "rule/x", later) {
		t.Fatalf("insert after the window reported as repeat")
	}
	if n := len(e.notifyEdges); n != 1 {
		t.Fatalf("expired sweep left %d entries, want 1", n)
	}
}

// TestNotifyRuleID pins the rule identity: everything before the first ':'
// (the rising count lives after it), the whole Reason when there is none,
// truncated so a free-text AI Reason cannot inflate an entry.
func TestNotifyRuleID(t *testing.T) {
	long := make([]byte, notifyRuleMaxLen*2)
	for i := range long {
		long[i] = 'a'
	}
	cases := []struct{ in, want string }{
		{"rule/http_scanner_503: 56 events in 1m0s (threshold 15)", "rule/http_scanner_503"},
		{"rule/http_scanner_503: 121 events in 1m0s (threshold 15)", "rule/http_scanner_503"},
		{"no colon here", "no colon here"},
		{"", ""},
		{string(long), string(long[:notifyRuleMaxLen])},
	}
	for _, c := range cases {
		if got := notifyRuleID(c.in); got != c.want {
			t.Errorf("notifyRuleID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
