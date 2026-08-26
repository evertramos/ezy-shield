// SPDX-License-Identifier: AGPL-3.0-only

package decision

// ADR-0013 proof matrix, filter half (issue #560): authenticated peers
// keep immunity, unauthenticated ones lose it only after the grace
// window, and EVERY logind failure mode fails open to the ESTABLISHED-only
// behavior. The end-to-end half (daemon + re-check) lives in
// internal/daemon/authlockout_test.go.

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func sessionsOf(ok bool, ss ...string) func() (map[netip.Addr]bool, bool) {
	m := map[netip.Addr]bool{}
	for _, s := range ss {
		m[netip.MustParseAddr(s)] = true
	}
	return func() (map[netip.Addr]bool, bool) { return m, ok }
}

func TestAuthPeerFilter_Matrix(t *testing.T) {
	t.Parallel()
	operator := "192.0.2.10"  // interactive session — in logind
	agent := "192.0.2.11"     // non-interactive exec session — in logind too
	attacker := "203.0.113.9" // ESTABLISHED, never authenticated

	base := func() []netip.Addr { return addrs(operator, agent, attacker) }
	f := NewAuthenticatedPeerFilter(base, sessionsOf(true, operator, agent), 10*time.Second)

	clock := time.Now()
	f.now = func() time.Time { return clock }

	// Within the grace window: everyone still immune (race coverage).
	got := f.Peers()
	if len(got) != 3 {
		t.Fatalf("within grace all peers stay immune, got %v", got)
	}

	// Past the grace window: only authenticated peers keep immunity.
	clock = clock.Add(11 * time.Second)
	got = f.Peers()
	if len(got) != 2 {
		t.Fatalf("past grace = %v, want operator+agent only", got)
	}
	for _, p := range got {
		if p == netip.MustParseAddr(attacker) {
			t.Fatalf("unauthenticated held socket kept immunity past grace")
		}
	}
}

func TestAuthPeerFilter_LogindUnavailableFailsOpen(t *testing.T) {
	t.Parallel()
	base := func() []netip.Addr { return addrs("203.0.113.9") }
	f := NewAuthenticatedPeerFilter(base, sessionsOf(false), 10*time.Second)
	clock := time.Now()
	f.now = func() time.Time { return clock }
	clock = clock.Add(time.Hour) // far past any grace

	if got := f.Peers(); len(got) != 1 {
		t.Fatalf("logind unavailable must fail open to ESTABLISHED-only, got %v", got)
	}
}

func TestAuthPeerFilter_ReconnectRestartsGrace(t *testing.T) {
	t.Parallel()
	present := true
	base := func() []netip.Addr {
		if present {
			return addrs("203.0.113.9")
		}
		return nil
	}
	f := NewAuthenticatedPeerFilter(base, sessionsOf(true), 5*time.Second)
	clock := time.Now()
	f.now = func() time.Time { return clock }

	_ = f.Peers() // first sight
	clock = clock.Add(6 * time.Second)
	if got := f.Peers(); len(got) != 0 {
		t.Fatalf("past grace without session must drop, got %v", got)
	}
	present = false
	_ = f.Peers() // connection gone: tracking pruned
	present = true
	clock = clock.Add(time.Second)
	if got := f.Peers(); len(got) != 1 {
		t.Fatalf("a fresh reconnect must restart the grace window, got %v", got)
	}
}

// ── logind reader ────────────────────────────────────────────────────────────

func withLoginctl(t *testing.T, fn func(args ...string) ([]byte, error)) {
	t.Helper()
	orig := execLoginctl
	execLoginctl = func(_ context.Context, args ...string) ([]byte, error) { return fn(args...) }
	t.Cleanup(func() { execLoginctl = orig })
}

func TestLogindRemoteHosts_ParsesSessions(t *testing.T) {
	withLoginctl(t, func(args ...string) ([]byte, error) {
		if args[0] == "list-sessions" {
			return []byte("  3 1000 evert  -    pts/0\n  7 1000 evert  -    -\n 12 0 root seat0 tty1\n"), nil
		}
		// show-session --value: one RemoteHost line per session; blank for
		// the local seat session.
		return []byte("192.0.2.10\n192.0.2.11\n\n"), nil
	})
	hosts, ok := logindRemoteHosts(context.Background())
	if !ok || len(hosts) != 2 {
		t.Fatalf("hosts=%v ok=%v, want two remote sessions", hosts, ok)
	}
	if !hosts[netip.MustParseAddr("192.0.2.10")] || !hosts[netip.MustParseAddr("192.0.2.11")] {
		t.Fatalf("hosts=%v", hosts)
	}
}

func TestLogindRemoteHosts_FailureModes(t *testing.T) {
	// loginctl missing/erroring → unavailable.
	withLoginctl(t, func(...string) ([]byte, error) { return nil, errors.New("no loginctl") })
	if _, ok := logindRemoteHosts(context.Background()); ok {
		t.Fatalf("loginctl error must report unavailable")
	}

	// A hostname RemoteHost (UseDNS yes) cannot be matched to peers —
	// narrowing anything could strip a real operator: unavailable.
	withLoginctl(t, func(args ...string) ([]byte, error) {
		if args[0] == "list-sessions" {
			return []byte("3 1000 evert - pts/0\n"), nil
		}
		return []byte("workstation.lan\n"), nil
	})
	if _, ok := logindRemoteHosts(context.Background()); ok {
		t.Fatalf("hostname RemoteHost must report unavailable (fail open)")
	}

	// No sessions at all is a VALID answer (empty set, ok=true).
	withLoginctl(t, func(args ...string) ([]byte, error) { return []byte(""), nil })
	hosts, ok := logindRemoteHosts(context.Background())
	if !ok || len(hosts) != 0 {
		t.Fatalf("empty session list must be ok=true, got %v %v", hosts, ok)
	}
}
