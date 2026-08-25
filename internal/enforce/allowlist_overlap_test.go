package enforce

// Regression tests for issue #358 items 6 and 7.

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// TestTargetOverlapsAllowlist pins the belt-and-suspenders semantics: prefix
// targets use Overlaps (the Gate's semantics), addresses use Contains. The
// old base-address-only check let a CIDR ban that CONTAINS an allowlisted
// host pass — the documented protection against accidental direct invocation
// did not hold for CIDR targets.
func TestTargetOverlapsAllowlist(t *testing.T) {
	t.Parallel()
	allow := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.128/32"),
		netip.MustParsePrefix("2001:db8:aa::/48"),
	}
	cases := []struct {
		name string
		t    sdk.Target
		want bool
	}{
		{"address inside allowlist", sdk.Target{IP: netip.MustParseAddr("192.0.2.128")}, true},
		{"address outside allowlist", sdk.Target{IP: netip.MustParseAddr("192.0.2.1")}, false},
		// The failure class: base address 192.0.2.0 is NOT allowlisted, but
		// the /24 contains the allowlisted host .128.
		{"prefix containing allowlisted host", sdk.Target{Prefix: netip.MustParsePrefix("192.0.2.0/24")}, true},
		{"prefix inside allowlisted range", sdk.Target{Prefix: netip.MustParsePrefix("2001:db8:aa:1::/64")}, true},
		{"disjoint prefix", sdk.Target{Prefix: netip.MustParsePrefix("198.51.100.0/24")}, false},
		{"empty target", sdk.Target{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := targetOverlapsAllowlist(tc.t, allow); got != tc.want {
				t.Errorf("targetOverlapsAllowlist(%+v) = %v, want %v", tc.t, got, tc.want)
			}
		})
	}
}

// TestNftables_BanRefusesPrefixContainingAllowlistedHost drives the real Ban
// path: the enforcer-internal guard must refuse the CIDR without contacting
// the helper.
func TestNftables_BanRefusesPrefixContainingAllowlistedHost(t *testing.T) {
	t.Parallel()
	e := New("/nonexistent.sock", []netip.Prefix{netip.MustParsePrefix("192.0.2.128/32")})
	err := e.Ban(context.Background(), sdk.Target{Prefix: netip.MustParsePrefix("192.0.2.0/24")})
	if err == nil || !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("CIDR ban overlapping an allowlisted host must be refused, got: %v", err)
	}
}

// TestWithNames_InvalidNamesErrorInsteadOfPanic (issue #358 item 6): invalid
// names reaching WithNames used to panic in library code; they must instead
// mark the enforcer broken so every call errors out.
func TestWithNames_InvalidNamesErrorInsteadOfPanic(t *testing.T) {
	t.Parallel()
	e := New("/nonexistent.sock", nil, WithNames("inet bad;name", "set"))
	err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("192.0.2.9")})
	if err == nil || !strings.Contains(err.Error(), "invalid nftables names") {
		t.Fatalf("invalid WithNames must surface as an error on use, got: %v", err)
	}
}
