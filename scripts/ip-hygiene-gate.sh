#!/usr/bin/env bash
#
# ip-hygiene-gate.sh — CI gate for AGENTS.md Hard Rule 8 (no real personal data).
#
# Scans the ADDED lines of a diff range for IPv4/IPv6 literals outside the
# documentation/private ranges, in the paths where every IP must be an
# example: tests, fixtures/, and configs/. Paths whose real IP data is the
# product (internal/cdndetect/ — published CDN ranges) are excluded.
#
# Allowlist, not denylist (issue #143): any real IP is forbidden by
# definition, so the gate accepts only ranges that can never identify a host:
#   IPv4: RFC 5737 (192.0.2/24, 198.51.100/24, 203.0.113/24), RFC 1918,
#         loopback, 0/8, link-local 169.254/16, CGNAT 100.64/10,
#         benchmark 198.18/15, 6to4 anycast 192.88.99/24, and >=224/8
#         (multicast/reserved, which also covers broadcast and netmask
#         literals such as 255.255.255.0).
#   IPv6: RFC 3849 (2001:db8::/32), ::/::1, link-local fe80::/10,
#         ULA fc00::/7, multicast ff00::/8.
#
# Known limits (documented, accepted): an all-digit IPv6 literal without "::"
# is indistinguishable from timestamp noise and is skipped; usernames and SSH
# key fingerprints have no reserved example range and remain review-only
# (see Hard Rule 8).
#
# Usage:
#   scripts/ip-hygiene-gate.sh <base-ref>    gate HEAD's added lines vs base
#   scripts/ip-hygiene-gate.sh --self-test   run built-in test vectors

set -euo pipefail

# Paths where every IP literal must be an example (git pathspecs).
SCOPE=('*_test.go' 'fixtures/' 'configs/')
EXCLUDE=(':!internal/cdndetect/')

# ipv4_offenders: stdin → public IPv4 literals outside the allowed ranges.
ipv4_offenders() {
	grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' |
		awk -F. '
			$1>255 || $2>255 || $3>255 || $4>255 {next}   # not an address
			$1==0 || $1==10 || $1==127 || $1>=224 {next}  # 0/8, 10/8, loopback, mcast/reserved
			$1==192 && $2==168 {next}                     # RFC 1918
			$1==172 && $2>=16 && $2<=31 {next}            # RFC 1918
			$1==169 && $2==254 {next}                     # link-local
			$1==100 && $2>=64 && $2<=127 {next}           # CGNAT
			$1==192 && $2==0 && $3==2 {next}              # RFC 5737 TEST-NET-1
			$1==198 && $2==51 && $3==100 {next}           # RFC 5737 TEST-NET-2
			$1==203 && $2==0 && $3==113 {next}            # RFC 5737 TEST-NET-3
			$1==198 && ($2==18 || $2==19) {next}          # RFC 2544 benchmark
			$1==192 && $2==88 && $3==99 {next}            # 6to4 anycast
			{print}' |
		sort -u
}

# ipv6_offenders: stdin → IPv6-looking literals outside the allowed ranges.
# A candidate must contain a hex letter or "::" (filters timestamps), and
# MAC addresses (six 2-hex-digit groups) are skipped.
ipv6_offenders() {
	grep -oiE '\b([0-9a-f]{1,4}:){2,7}:?[0-9a-f]{1,4}\b|([0-9a-f]{1,4})?::[0-9a-f:]*[0-9a-f]' |
		grep -iE '[a-f]|::' |
		grep -viE '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' |
		grep -viE '^(2001:0?db8(:|$)|fe80:|f[cd][0-9a-f]{0,2}:|ff[0-9a-f]{0,2}:)' |
		grep -vxiE '::1?' |
		sort -u
}

self_test() {
	local rc=0

	check() { # name, expected, actual
		if [ "$2" = "$3" ]; then
			echo "  ok: $1"
		else
			echo "  FAIL: $1 — expected [$2], got [$3]"
			rc=1
		fi
	}

	echo "self-test: ipv4"
	check "real public IPv4 flagged" "51.77.145.130" \
		"$(printf 'Failed password from 51.77.145.130 port 22' | ipv4_offenders)"
	check "public DNS flagged (doc ranges only)" "8.8.8.8" \
		"$(printf 'nameserver 8.8.8.8' | ipv4_offenders)"
	check "doc/private/netmask/version pass" "" \
		"$(printf '192.0.2.1 198.51.100.7 203.0.113.9 10.1.2.3 255.255.255.0 172.16.0.1 v1.2.3.999' | ipv4_offenders)"

	echo "self-test: ipv6"
	check "real IPv6 flagged" "2804:8d4:2ab:15c0:f499:c95a:6962:9753" \
		"$(printf 'from 2804:8d4:2ab:15c0:f499:c95a:6962:9753 port 22' | ipv6_offenders)"
	check "doc/link-local/ULA/mcast/loopback pass" "" \
		"$(printf '2001:db8::1 2001:db8:2ab::9 fe80::1 fd00::1 ff02::1 ::1' | ipv6_offenders)"
	check "timestamps and MACs pass" "" \
		"$(printf 'at 12:34:56 mac aa:bb:cc:dd:ee:ff' | ipv6_offenders)"

	[ "$rc" -eq 0 ] && echo "self-test: all green"
	return "$rc"
}

gate() {
	local base="$1"
	local added off4 off6

	added=$(git diff "$base"...HEAD -- "${SCOPE[@]}" "${EXCLUDE[@]}" |
		grep -E '^\+' | grep -vE '^\+\+\+' || true)

	off4=$(printf '%s\n' "$added" | ipv4_offenders || true)
	off6=$(printf '%s\n' "$added" | ipv6_offenders || true)

	if [ -z "$off4" ] && [ -z "$off6" ]; then
		echo "ip-hygiene-gate: no non-example IP literals added (scope: ${SCOPE[*]})"
		return 0
	fi

	echo "::error::Non-example IP literal(s) added to tests/fixtures/configs." \
		"AGENTS.md Hard Rule 8: use RFC 5737 (192.0.2.0/24, 198.51.100.0/24," \
		"203.0.113.0/24) or RFC 3849 (2001:db8::/32) instead."
	[ -n "$off4" ] && printf 'IPv4:\n%s\n' "$off4"
	[ -n "$off6" ] && printf 'IPv6:\n%s\n' "$off6"
	echo
	echo "Offending added lines:"
	printf '%s\n' "$added" | grep -nF -f <(printf '%s\n%s\n' "$off4" "$off6" | sed '/^$/d') | head -20
	return 1
}

case "${1:-}" in
--self-test) self_test ;;
'') echo "usage: $0 <base-ref> | --self-test" >&2 && exit 2 ;;
*) gate "$1" ;;
esac
