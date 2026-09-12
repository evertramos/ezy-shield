// SPDX-License-Identifier: AGPL-3.0-only

package parser

import (
	"net/netip"
	"strings"
)

// clientFromXFF returns the client address behind a chain of trusted
// proxies, given the X-Forwarded-For value the innermost proxy logged.
//
// Every proxy APPENDS the address it accepted the connection from, so the
// header reads "<whatever the client sent>, <hop 1>, <hop 2>, …, <last
// hop before us>". Only the suffix that trusted proxies wrote can be
// believed; the client controls everything to the left of it. The client
// is therefore the RIGHTMOST hop that is not a trusted proxy (issue #612 —
// taking the leftmost hop let a client behind a CDN attribute its traffic,
// strikes and ban to any address it named). Unparseable tokens are skipped:
// a client cannot place one to the right of the addresses the proxies
// appended. ok is false when no untrusted hop exists (the connection came
// through trusted proxies only, or the header was empty).
func clientFromXFF(xff string, trusted func(netip.Addr) bool) (netip.Addr, bool) {
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		if part == "" || part == "-" {
			continue
		}
		ip, err := parseIP(part)
		if err != nil {
			continue
		}
		if !trusted(ip) {
			return ip, true
		}
	}
	return netip.Addr{}, false
}
