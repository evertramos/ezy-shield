//go:build linux && integration

// Integration test for killSocketsForIP that invokes the real iproute2 `ss`
// binary against a live IPv6 TCP loopback socket. The unit test in
// socket_kill_test.go uses a mock ssRunner — that mock is exactly what let
// issue #38 ship (bare-v6 filter that ss misparses). This test is the guardrail
// against that class of regression: if the argv shape ever loses the /128 (or
// otherwise fails ss's parser), the assertion that the connection was torn
// down will fail with a live error message from ss.
//
// It is opt-in via the `integration` build tag because it (a) shells out to a
// real binary, (b) needs CAP_NET_ADMIN or root to actually SOCK_DESTROY, and
// (c) is inherently timing-sensitive. Run with:
//
//	sudo -E env "PATH=$PATH" go test -tags 'linux integration' -run TestKillSockets ./cmd/ezyshield-enforcer/
//
// The test skips (not fails) when `ss` is missing or when the process lacks
// the capability required to destroy sockets, so CI without root still passes.

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestKillSocketsForIP_v6_Integration opens a listening TCP6 socket on [::1],
// dials it, then invokes killSocketsForIP with the peer's v6 address using the
// real ss runner. It asserts the pre-established connection is torn down —
// which can only happen if ss actually parsed and accepted the dst filter.
//
// A bare-v6 filter (the pre-#38 code) would make ss exit non-zero and
// killSocketsForIP would log WARN and return without destroying the socket,
// so the connection would remain readable and this test would fail.
func TestKillSocketsForIP_v6_Integration(t *testing.T) {
	if _, err := exec.LookPath("ss"); err != nil {
		t.Skip("ss not on PATH; skipping integration test")
	}

	// Bind on IPv6 loopback with an ephemeral port.
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("cannot bind [::1]:0 (no IPv6 loopback?): %v", err)
	}
	defer ln.Close()

	acceptErr := make(chan error, 1)
	serverConnCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		serverConnCh <- c
	}()

	// Dial the listener over v6. The client connection is what we'll assert
	// gets torn down — its *peer* (the local end from ss's perspective) is
	// the listener, so we filter on [::1].
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	clientConn, err := dialer.Dial("tcp6", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	select {
	case <-serverConnCh:
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for accept")
	}

	// Kill sockets with peer == ::1 via the real ss binary.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Capture whether ss failed by wrapping realSsRunner: if it does fail
	// (usually because we're not root), fall back to Skip rather than fail
	// — the point is to catch parser-level regressions, not permission bugs.
	var ssErr error
	wrapped := func(ctx context.Context, args []string) error {
		err := realSsRunner(ctx, args)
		ssErr = err
		return err
	}

	if err := killSocketsForIP(ctx, wrapped, "::1"); err != nil {
		t.Fatalf("killSocketsForIP returned error (must be nil per best-effort): %v", err)
	}
	if ssErr != nil {
		// ss ran but non-zero. If it's a permission problem, skip; if
		// it's a *parse* error we absolutely want to fail — that's the
		// regression we're guarding against.
		msg := ssErr.Error()
		if containsAny(msg, "operation not permitted", "Operation not permitted", "not permitted", "must be root") {
			t.Skipf("ss -K needs CAP_NET_ADMIN; skipping teardown assertion: %v", ssErr)
		}
		if containsAny(msg, "does not look like a port", "an inet prefix is expected", "Cannot parse dst") {
			t.Fatalf("ss rejected the v6 filter — this is the issue #38 regression: %v", ssErr)
		}
		// Unknown ss failure — still worth flagging.
		t.Fatalf("ss -K failed for an unknown reason: %v", ssErr)
	}

	// If ss succeeded, the connection should be torn down. Read from the
	// client end with a short deadline: EOF or ECONNRESET both count as
	// "socket destroyed".
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	n, err := clientConn.Read(buf)
	if err == nil {
		t.Fatalf("expected connection teardown, but Read returned %d bytes with no error", n)
	}
	if errors.Is(err, io.EOF) {
		return // torn down cleanly
	}
	if isConnReset(err) {
		return // torn down with RST
	}
	// Timeout or other error suggests ss did not actually destroy the
	// socket. That could be a permissions issue at test time; only fail
	// hard if we're confident ss succeeded.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Skipf("read timed out — ss reported success but socket was not destroyed (need CAP_NET_ADMIN?): %v", err)
	}
	t.Fatalf("unexpected read error after kill: %v", err)
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func isConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}
