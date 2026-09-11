// SPDX-License-Identifier: AGPL-3.0-only

package enforce_test

// Regression tests for issue #615: the helper's whole-second timeout must
// never be 0 for a ban that still has time left — 0 is "permanent".

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestBan_SubSecondTTLRoundsUpToOneSecond(t *testing.T) {
	for _, tc := range []struct {
		ttl  time.Duration
		want int64
	}{
		{600 * time.Millisecond, 1},
		{time.Millisecond, 1},
		{time.Second, 1},
		{90*time.Second + 200*time.Millisecond, 91},
		{time.Hour, 3600},
		{0, 0}, // permanent stays permanent
	} {
		ms := newMockHelper(t)
		e := enforce.New(ms.sock, nil)
		if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("203.0.113.9"), TTL: tc.ttl}); err != nil {
			t.Fatalf("Ban(%v): %v", tc.ttl, err)
		}
		reqs := ms.recorded()
		if len(reqs) == 0 || reqs[len(reqs)-1].Verb != "add" {
			t.Fatalf("Ban(%v): no add request recorded", tc.ttl)
		}
		if got := reqs[len(reqs)-1].TTLSeconds; got != tc.want {
			t.Errorf("Ban(%v): TTLSeconds = %d, want %d", tc.ttl, got, tc.want)
		}
	}
}

func TestSync_SubSecondTTLRoundsUpToOneSecond(t *testing.T) {
	ms := newMockHelper(t)
	ms.setListIPs(nil)
	e := enforce.New(ms.sock, nil)
	if err := e.Sync(context.Background(), []sdk.Target{{IP: netip.MustParseAddr("203.0.113.10"), TTL: 400 * time.Millisecond}}); err != nil {
		t.Fatal(err)
	}
	for _, r := range ms.recorded() {
		if r.Verb == "add" && r.TTLSeconds != 1 {
			t.Fatalf("Sync add TTLSeconds = %d, want 1 (never 0 for a live ban)", r.TTLSeconds)
		}
	}
}
