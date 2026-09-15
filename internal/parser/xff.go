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
// header reads "<whatever the client sent>, <hop 1>, …, <last hop before
// us>". Only the suffix that trusted proxies wrote can be believed; the
// client controls everything to the left of it. The client is therefore the
// RIGHTMOST hop that is not a trusted proxy (issue #612 — taking the
// leftmost hop let a client behind a CDN attribute its traffic, strikes and
// ban to any address it named).
//
// The walk stops at the first token, from the right, that is not an
// address: proxies that append "unknown", an obfuscated identifier
// (RFC 7239 style) or a value this code cannot parse have hidden the
// client, and walking further left would land in client-controlled text —
// the framing vector again. ok=false then, and the caller keeps
// remote_addr. Tokens may carry a port ("203.0.113.9:1234", "[2001:db8::7]:443")
// as some proxies write; IPv4-mapped IPv6 spellings are unmapped before the
// trusted check and before being returned.
func clientFromXFF(xff string, trusted func(netip.Addr) bool) (netip.Addr, bool) {
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		if part == "" {
			continue
		}
		ip, ok := parseHop(part)
		if !ok {
			return netip.Addr{}, false
		}
		if !trusted(ip) {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// parseHop parses one X-Forwarded-For token: a bare address, a bracketed
// IPv6 address, or either with a port. The result is unmapped.
func parseHop(tok string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(tok); err == nil {
		return ap.Addr().Unmap(), true
	}
	if ip, err := parseIP(tok); err == nil {
		return ip.Unmap(), true
	}
	return netip.Addr{}, false
}
