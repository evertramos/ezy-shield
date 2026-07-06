package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
)

// ssRunner abstracts `ss` execution so tests can inject a mock.
// It mirrors the nftRunner pattern (nft.go): a single function type that
// takes args and returns an error, with a realSsRunner default that shells
// out to the iproute2 binary.
type ssRunner func(ctx context.Context, args []string) error

// realSsRunner executes `ss <args...>` and returns non-nil on non-zero exit,
// wrapping stderr in the error message for the caller's WARN log.
func realSsRunner(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, "ss", args...) //nolint:gosec // args are constructed from validated IPs, never from log data
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ss %v: %w\n%s", args, err, bytes.TrimSpace(out))
	}
	return nil
}

// ssFilterValue formats an IP for use as the value of the `dst` filter in
// `ss -K dst <value>`. It exists because ss's dst-filter parser reads a bare
// value as ADDR[:PORT]: for a bare IPv6 that means the last hextet is treated
// as a port ("does not look like a port" / "an inet prefix is expected" — see
// issue #38 for the live-host traces). Two unambiguous v6 forms are accepted
// by iproute2 — bracketed `[v6]` and prefix `v6/128`; we use the /128 prefix
// because it doubles as an explicit host-scope indicator when an operator
// eyeballs `ps auxf`.
//
// v4 is returned byte-identical to input so the working path stays unchanged.
//
// IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is unmapped to its v4 form. Rationale:
// the kernel presents connections landing on a dual-stack listener as v4 in
// the socket-diag output that ss -K consumes, so unmapping keeps the filter
// aligned with what ss actually sees; it also collapses the case to the
// well-tested v4 path.
//
// The addr must already be a valid netip.Addr (callers use netip.ParseAddr);
// this function assumes .IsValid() and does not re-validate.
func ssFilterValue(addr netip.Addr) string {
	// Unmap v4-mapped v6 to bare v4 (see comment above).
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is6() {
		// Drop zone (e.g. "fe80::1%eth0") — ss's dst filter doesn't
		// understand zone IDs, and a link-local peer that reached us
		// through a specific interface is already unambiguous to the
		// kernel's socket-diag lookup. Keeping the zone would just
		// re-introduce the "extra colon" ambiguity we're fixing.
		if addr.Zone() != "" {
			addr = addr.WithZone("")
		}
		return addr.String() + "/128"
	}
	return addr.String()
}

// killSocketsForIP forcibly closes any TCP socket whose peer address matches ip.
// Uses `ss -K dst <filter>` which drives the SOCK_DESTROY netlink op (kernel
// >= 4.5, iproute2 >= 4.5).
//
// Address-family handling: the caller passes a string form, but ss's dst-filter
// parser is family-sensitive (a bare IPv6 collides with ADDR:PORT syntax), so
// we normalise via ssFilterValue: v4 unchanged, v6 as `<addr>/128`, v4-mapped-v6
// unmapped to v4. See ssFilterValue and issue #38 for details.
//
// This is paired with the raw/prerouting sinkhole from PR #25 (ADR-0007). The
// sinkhole stops NEW connections but does not tear down TCP flows established
// before the ban — see issue #30 for the live evidence bundle where banned IPs
// kept hitting a Docker-published container for up to 231 minutes because
// docker-proxy's userspace socket already held the connection.
//
// Best-effort semantics (Hard Rule §1 — safety invariant): if `ss` is missing,
// the address is unparseable, or the command fails, we log at WARN and return
// nil. A successful nft ban must never be rolled back because socket teardown
// failed. WARN (not ERROR) is deliberate: this path is expected to fail on
// hosts without iproute2 or with older kernels, and ERROR would generate false
// pages (SECURITY-REVIEW.md §10 style choice).
func killSocketsForIP(ctx context.Context, run ssRunner, ip string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		// Caller already validates via netip in the server; treat an
		// unparseable value defensively rather than passing garbage to ss.
		slog.WarnContext(ctx, "enforcer: ss -K skipped; unparseable IP (ban still committed)",
			slog.String("ip", ip), slog.String("err", err.Error()))
		return nil
	}
	filter := ssFilterValue(addr)
	if err := run(ctx, []string{"-K", "dst", filter}); err != nil {
		slog.WarnContext(ctx, "enforcer: ss -K failed; ban is committed, pre-ban TCP sessions may persist",
			slog.String("ip", ip), slog.String("filter", filter), slog.String("err", err.Error()))
		return nil
	}
	slog.DebugContext(ctx, "enforcer: pre-ban TCP sessions killed", slog.String("ip", ip), slog.String("filter", filter))
	return nil
}
