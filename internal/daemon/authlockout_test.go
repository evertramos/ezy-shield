// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// ADR-0013 proof matrix, end-to-end half (issue #560): with the
// authenticated-peer filter installed as the engine's SSH-peer probe, the
// kylian attack (ESTABLISHED socket, never authenticated) is BANNED once
// the grace window expires — while an authenticated session (interactive
// or exec, i.e. present in logind) is never banned, exactly as before.
// Wiring is identical to the daemon's own (SetSSHPeerProbe), so both
// immunity layers see the narrowed set.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/decision"
)

// authFilterProbe builds the ADR-0013 filter over an always-ESTABLISHED
// base for ip, with a fake logind answer and a tiny grace for tests.
func authFilterProbe(ip netip.Addr, authenticated, logindOK bool, grace time.Duration) func() []netip.Addr {
	sessions := map[netip.Addr]bool{}
	if authenticated {
		sessions[ip.Unmap()] = true
	}
	f := decision.NewAuthenticatedPeerFilter(
		func() []netip.Addr { return []netip.Addr{ip} },
		func() (map[netip.Addr]bool, bool) { return sessions, logindOK },
		grace,
	)
	return f.Peers
}

// TestADR0013_HeldUnauthenticatedSocket_GetsBanned: the #559 attacker —
// holds the socket, never logs in — loses immunity after the grace and
// the deferred re-check converts the evidence into a ban.
func TestADR0013_HeldUnauthenticatedSocket_GetsBanned(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attacker := netip.MustParseAddr("203.0.113.66")
	enf := &fakeEnforcer{}
	d, _ := newRecheckDaemon(t, enf, authFilterProbe(attacker, false, true, 30*time.Millisecond))
	// The engine caches the peer probe for SSHPeerCacheTTL (2s); the
	// harness default re-check delay (20ms) would burn the whole retry
	// budget inside one cached (still-immune) read. Use a delay that
	// keeps re-checks alive past the cache expiry — production keeps
	// this invariant by construction (delay = 2×TTL).
	d.sshRecheckDelay = 300 * time.Millisecond

	go d.runSSHRecheck(ctx)
	feedBurst(ctx, d, attacker, 6)

	if !waitFor(10*time.Second, func() bool { return enf.BanCount() >= 1 }) {
		t.Fatalf("held-but-unauthenticated socket was never banned — ADR-0013 not effective")
	}
}

// TestADR0013_AuthenticatedPeer_NeverBanned: a peer present in logind
// (operator shell or agent exec session) keeps full immunity forever.
func TestADR0013_AuthenticatedPeer_NeverBanned(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	operator := netip.MustParseAddr("192.0.2.88")
	enf := &fakeEnforcer{}
	d, _ := newRecheckDaemon(t, enf, authFilterProbe(operator, true, true, 30*time.Millisecond))

	go d.runSSHRecheck(ctx)
	feedBurst(ctx, d, operator, 6)
	time.Sleep(400 * time.Millisecond) // several grace windows + re-checks
	if enf.BanCount() != 0 {
		t.Fatalf("authenticated peer was banned %d time(s) — Hard Rule 1 broken", enf.BanCount())
	}
}

// TestADR0013_LogindDown_FailsOpen_NeverBanned: logind unavailable must
// reproduce today's behavior exactly — the ESTABLISHED peer stays immune
// even without a session (fail open toward the operator).
func TestADR0013_LogindDown_FailsOpen_NeverBanned(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	peer := netip.MustParseAddr("192.0.2.89")
	enf := &fakeEnforcer{}
	d, _ := newRecheckDaemon(t, enf, authFilterProbe(peer, false, false, 30*time.Millisecond))

	go d.runSSHRecheck(ctx)
	feedBurst(ctx, d, peer, 6)
	time.Sleep(400 * time.Millisecond)
	if enf.BanCount() != 0 {
		t.Fatalf("logind outage enabled a ban that today's code refuses — fail-open broken")
	}
}

// TestADR0013_FlagOffByDefault: the policy default keeps the legacy
// behavior (rollout is opt-in per the ADR).
func TestADR0013_FlagOffByDefault(t *testing.T) {
	t.Parallel()
	d, _ := newRecheckDaemon(t, &fakeEnforcer{}, func() []netip.Addr { return nil })
	if d.policy.RequireAuthenticatedPeer() {
		t.Fatalf("anti_lockout.require_authenticated must default to false")
	}
}
