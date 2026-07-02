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

// TestProbeSocket_Stale: a leftover socket file with no listener behind it must
// be treated as safe to remove — otherwise a crashed daemon's stale socket
// would permanently block restart.
func TestProbeSocket_Stale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ezyshield.sock")
	// Create the file but don't bind a listener.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ProbeSocket(context.Background(), path); err != nil {
		t.Fatalf("expected nil for stale socket, got: %v", err)
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
