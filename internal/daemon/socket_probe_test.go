package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestProbeSocket_Missing: no file at path → safe to bind.
func TestProbeSocket_Missing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ezyshield.sock")
	if err := ProbeSocket(context.Background(), path); err != nil {
		t.Fatalf("expected nil for missing socket, got: %v", err)
	}
}

// TestProbeSocket_Stale: a genuine stale unix-socket file (real socket that had
// a listener, now gone) must be treated as safe to remove — otherwise a
// crashed daemon's leftover socket would permanently block restart. We create
// a real socket by binding then closing without unlinking.
func TestProbeSocket_Stale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ezyshield.sock")
	// Bind then close: the file remains on disk with the socket mode bit set,
	// but no process is listening — exactly the crashed-daemon scenario.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	// Confirm the file survived Close (older Go versions unlink on Close;
	// current behavior keeps the file, which is what we want to test).
	fi, err := os.Stat(path)
	if err != nil {
		t.Skipf("this Go/OS unlinks unix socket on Close; nothing to probe: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected socket mode bit, got %s", fi.Mode())
	}
	if err := ProbeSocket(context.Background(), path); err != nil {
		t.Fatalf("expected nil for stale socket, got: %v", err)
	}
}

// TestProbeSocket_NonSocket: if the path exists but is a regular file (or
// anything other than a unix socket), ProbeSocket must refuse — silently
// removing an unknown file would be data loss. Robustness fix flagged in
// review.
func TestProbeSocket_NonSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-sock")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ProbeSocket(context.Background(), path)
	if err == nil {
		t.Fatal("expected error for regular file at socket path, got nil")
	}
	if !errors.Is(err, ErrSocketInUse) {
		t.Fatalf("expected ErrSocketInUse for non-socket, got: %v", err)
	}
}

// TestProbeSocket_Live: a bound socket must be reported as in-use, so a manual
// `ezyshield watch` refuses to clobber a live systemd-managed daemon (#14).
func TestProbeSocket_Live(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ezyshield.sock")
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	err = ProbeSocket(context.Background(), path)
	if err == nil {
		t.Fatal("expected ErrSocketInUse for live socket, got nil")
	}
	if !errors.Is(err, ErrSocketInUse) {
		t.Fatalf("expected ErrSocketInUse, got: %v", err)
	}
}
