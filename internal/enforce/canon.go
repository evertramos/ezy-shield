// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import "net/netip"

// CanonicalIPKey renders an address or prefix the way nftables itself
// prints a set element (issue #592): a single-host prefix (/32, /128) is its
// bare address, any other prefix is masked, an address is unmapped. Both
// sides of every reconcile — the desired state built from netip values and
// the current state parsed from `nft list set` — must use this spelling, or
// "192.0.2.10/32" (wanted) and "192.0.2.10" (listed) never match and each
// SyncAllowlist adds the one (a kernel no-op) and deletes the other (the
// same element), stripping every single-host allowlist entry from the
// kernel @allowed set. Input that is neither an address nor a prefix is
// returned unchanged so validation errors surface where they are checked.
func CanonicalIPKey(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.IsSingleIP() {
			return p.Addr().Unmap().String()
		}
		return p.Masked().String()
	}
	return s
}
