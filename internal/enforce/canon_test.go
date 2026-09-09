// SPDX-License-Identifier: AGPL-3.0-only

package enforce_test

// Regression tests for issue #592: the reconcilers must compare and send
// elements in nftables' own spelling (a /32 is a bare address), or every
// SyncAllowlist strips single-host entries from the kernel @allowed set.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestCanonicalIPKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.10":        "192.0.2.10",
		"192.0.2.10/32":     "192.0.2.10",
		"::ffff:192.0.2.10": "192.0.2.10",
		"2001:db8::7/128":   "2001:db8::7",
		"2001:db8::7":       "2001:db8::7",
		"198.51.100.7/24":   "198.51.100.0/24",
		"2001:db8::/64":     "2001:db8::/64",
		"not-an-ip":         "not-an-ip",
		"192.0.2.10/33":     "192.0.2.10/33", // invalid prefix: left for validation to reject
	} {
		if got := enforce.CanonicalIPKey(in); got != want {
			t.Errorf("CanonicalIPKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func rpcCounts(reqs []enforce.Request) map[string][]string {
	out := map[string][]string{}
	for _, r := range reqs {
		out[r.Verb] = append(out[r.Verb], r.IP)
	}
	return out
}

// TestSyncAllowlist_SingleHostSpellings_NoChurn is the dogfood-host boot
// log: the kernel lists the admin /32 as a bare address, the policy carries
// it as a prefix — nothing must be added or removed.
func TestSyncAllowlist_SingleHostSpellings_NoChurn(t *testing.T) {
	ms := newMockHelper(t)
	ms.setAllowListIPs([]string{"192.0.2.10", "127.0.0.1", "::1", "2001:db8::/64"})
	e := enforce.New(ms.sock, nil)
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.10/32"),
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("2001:db8::/64"),
	}
	if err := e.SyncAllowlist(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got := rpcCounts(ms.recorded())
	if len(got["allow_add"]) != 0 || len(got["allow_del"]) != 0 {
		t.Fatalf("reconcile churned an already-correct kernel set: add=%v del=%v", got["allow_add"], got["allow_del"])
	}
}

// TestSyncAllowlist_SendsBareSpelling: a missing single-host entry is added
// with the spelling the kernel will list it under, so the next reconcile
// recognizes it.
func TestSyncAllowlist_SendsBareSpelling(t *testing.T) {
	ms := newMockHelper(t)
	ms.setAllowListIPs([]string{"198.51.100.9"}) // stale, must go
	e := enforce.New(ms.sock, nil)
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32"), netip.MustParsePrefix("2001:db8::7/128")}
	if err := e.SyncAllowlist(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got := rpcCounts(ms.recorded())
	adds := map[string]bool{}
	for _, ip := range got["allow_add"] {
		adds[ip] = true
	}
	if len(adds) != 2 || !adds["192.0.2.10"] || !adds["2001:db8::7"] {
		t.Errorf("allow_add spellings = %v, want bare 192.0.2.10 and 2001:db8::7", got["allow_add"])
	}
	if len(got["allow_del"]) != 1 || got["allow_del"][0] != "198.51.100.9" {
		t.Errorf("allow_del = %v, want only the stale 198.51.100.9", got["allow_del"])
	}
}

func TestAllowUnallow_SingleHostSentBare(t *testing.T) {
	ms := newMockHelper(t)
	e := enforce.New(ms.sock, nil)
	if err := e.Allow(context.Background(), netip.MustParsePrefix("192.0.2.10/32")); err != nil {
		t.Fatal(err)
	}
	if err := e.Unallow(context.Background(), netip.MustParsePrefix("2001:db8::7/128")); err != nil {
		t.Fatal(err)
	}
	if err := e.Allow(context.Background(), netip.MustParsePrefix("198.51.100.7/24")); err != nil {
		t.Fatal(err)
	}
	reqs := ms.recorded()
	want := []string{"192.0.2.10", "2001:db8::7", "198.51.100.0/24"}
	if len(reqs) != 3 {
		t.Fatalf("got %d requests, want 3", len(reqs))
	}
	for i, r := range reqs {
		if r.IP != want[i] {
			t.Errorf("request %d IP = %q, want %q", i, r.IP, want[i])
		}
	}
}

// TestSync_SingleHostPrefixTarget_NoChurn: a manual `ban 192.0.2.10/32`
// (Prefix target) against a kernel that lists 192.0.2.10 is in sync.
func TestSync_SingleHostPrefixTarget_NoChurn(t *testing.T) {
	ms := newMockHelper(t)
	ms.setListIPs([]string{"192.0.2.10"})
	e := enforce.New(ms.sock, nil)
	want := []sdk.Target{{Prefix: netip.MustParsePrefix("192.0.2.10/32"), TTL: time.Hour}}
	if err := e.Sync(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got := rpcCounts(ms.recorded())
	if len(got["add"]) != 0 || len(got["del"]) != 0 {
		t.Fatalf("spelling churn on the blocked set: add=%v del=%v", got["add"], got["del"])
	}
	if a, r, _ := e.LastSyncRepairs(); a != 0 || r != 0 {
		t.Errorf("repairs %d/%d, want 0/0", a, r)
	}
}
