package main

import (
	"net/netip"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// TestParseAllowlist_CanonicalizesMappedForms (issue #365): policy entries in
// the IPv4-mapped IPv6 spelling must reach the enforcers/Gate in plain IPv4
// form, or the entry protects nothing at the enforce layer.
func TestParseAllowlist_CanonicalizesMappedForms(t *testing.T) {
	policy := &config.Policy{
		Allowlist: []string{
			"::ffff:192.0.2.10",    // mapped bare IP
			"::ffff:192.0.2.0/120", // mapped CIDR (== 192.0.2.0/24)
			"198.51.100.7",         // plain bare IP
			"2001:db8::/32",        // real v6, untouched
		},
		AdminCIDRs: []string{"::ffff:203.0.113.0/124"}, // mapped admin CIDR (== 203.0.113.0/28)
	}

	got := parseAllowlist(policy)
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.10/32"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.7/32"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("203.0.113.0/28"),
	}
	if len(got) != len(want) {
		t.Fatalf("parseAllowlist returned %d prefixes, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prefix[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}
