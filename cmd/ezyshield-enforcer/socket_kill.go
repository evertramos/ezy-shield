package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
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

// killSocketsForIP forcibly closes any TCP socket whose peer address matches ip.
// Uses `ss -K dst <ip>` which drives the SOCK_DESTROY netlink op (kernel
// >= 4.5, iproute2 >= 4.5). One call handles v4 and v6 — ss parses the family
// from ip.
//
// This is paired with the raw/prerouting sinkhole from PR #25 (ADR-0007). The
// sinkhole stops NEW connections but does not tear down TCP flows established
// before the ban — see issue #30 for the live evidence bundle where banned IPs
// kept hitting a Docker-published container for up to 231 minutes because
// docker-proxy's userspace socket already held the connection.
//
// Best-effort semantics (Hard Rule §1 — safety invariant): if `ss` is missing
// or the command fails, we log at WARN and return nil. A successful nft ban
// must never be rolled back because socket teardown failed.
func killSocketsForIP(ctx context.Context, run ssRunner, ip string) error {
	if err := run(ctx, []string{"-K", "dst", ip}); err != nil {
		slog.WarnContext(ctx, "enforcer: ss -K failed; ban is committed, pre-ban TCP sessions may persist",
			slog.String("ip", ip), slog.String("err", err.Error()))
		return nil
	}
	slog.DebugContext(ctx, "enforcer: pre-ban TCP sessions killed", slog.String("ip", ip))
	return nil
}
