// SPDX-License-Identifier: AGPL-3.0-only

package e2e

// Invariant A (ban lifecycle) and the regressions of 2026-09, pinned
// end to end: real store → real engine → real daemon → real enforcer
// client → real helper → scripted kernel, on one virtual clock.

import (
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforcerd/nfttest"
)

// A1/A2 — a strike-1 ban reaches the kernel with its TTL, the kernel timer
// and the store agree on when it ends, the reaper removes the row, and the
// next burst climbs the ladder.
func TestBanLifecycle_StrikeTTLReaperLadder(t *testing.T) {
	s := start(t, options{armed: true})
	attacker := netip.MustParseAddr("203.0.113.61")

	s.sshBurst(attacker, 6)
	ban, ok := s.lastAction(attacker, "ban")
	if !ok || ban.Strike != 1 || ban.TTL != 5*time.Minute {
		t.Fatalf("first burst: action=%+v ok=%v, want strike 1 / 5m", ban, ok)
	}
	if !contains(s.blocked(), attacker.String()) {
		t.Fatalf("kernel blocked set = %v, want %s", s.blocked(), attacker)
	}
	if exp, ok := s.kernel.Expiry("blocked", attacker.String()); !ok || exp.Sub(s.clock.now()) != 5*time.Minute {
		t.Fatalf("kernel expiry = %v (present=%v), want +5m", exp, ok)
	}

	// The kernel timer fires at exactly the TTL; the reaper runs later.
	s.clock.advance(6 * time.Minute)
	if contains(s.blocked(), attacker.String()) {
		t.Fatalf("kernel still holds %s after its timeout", attacker)
	}
	if n, err := s.daemon.ExpireOnce(s.ctx); err != nil || n != 1 {
		t.Fatalf("reaper: n=%d err=%v, want 1", n, err)
	}
	if _, _, _, found, _ := s.store.GetBanInfo(s.ctx, attacker); found {
		t.Fatalf("store still reports an active ban after the reaper")
	}

	s.sshBurst(attacker, 6)
	ban, ok = s.lastAction(attacker, "ban")
	if !ok || ban.Strike != 2 || ban.TTL != time.Hour {
		t.Fatalf("second burst: action=%+v ok=%v, want strike 2 / 1h", ban, ok)
	}
	if exp, _ := s.kernel.Expiry("blocked", attacker.String()); exp.Sub(s.clock.now()) != time.Hour {
		t.Fatalf("kernel expiry after strike 2 = %v, want +1h", exp.Sub(s.clock.now()))
	}
}

// #603 — between the kernel timeout and the reaper, the attacker is not
// "already banned": the next burst becomes strike 2.
func TestBanLifecycle_ExpiredUnreapedBanDoesNotSuppress(t *testing.T) {
	s := start(t, options{armed: true})
	attacker := netip.MustParseAddr("203.0.113.62")
	s.sshBurst(attacker, 6)
	if _, ok := s.lastAction(attacker, "ban"); !ok {
		t.Fatal("no first ban")
	}
	s.clock.advance(5*time.Minute + time.Second) // kernel expired, reaper has not run
	s.sshBurst(attacker, 6)
	// The first ban-band decision of the new burst must be a strike-2 ban,
	// not already_banned (events after that ban are legitimately suppressed).
	first, ok := s.firstDecision(attacker)
	if !ok || first.Op != "ban" || first.Strike != 2 {
		t.Fatalf("post-expiry burst: first decision=%+v ok=%v, want a strike-2 ban", first, ok)
	}
	if !contains(s.blocked(), attacker.String()) {
		t.Fatalf("strike 2 not in the kernel: %v", s.blocked())
	}
}

// #590 — a stale /31 left in the kernel (the #589 migration shape) covers
// two wanted addresses: the reconcile must end with both members present
// and the /31 gone, and the helper's cache must agree (a second reconcile
// changes nothing).
func TestBanLifecycle_CoveredAddsRecoverAfterStaleInterval(t *testing.T) {
	a, b := netip.MustParseAddr("198.51.100.66"), netip.MustParseAddr("198.51.100.67")
	s := start(t, options{armed: true, seed: func(k *nfttest.Kernel) { k.Seed("blocked", "198.51.100.66/31", 0) }})
	for _, ip := range []netip.Addr{a, b} {
		if err := s.store.RecordManualBan(s.ctx, ip, 0, "test", false); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.daemon.Reconcile(s.ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := s.blocked()
	if !contains(got, a.String()) || !contains(got, b.String()) || contains(got, "198.51.100.66/31") {
		t.Fatalf("kernel after reconcile = %v, want both members and no /31", got)
	}
	mark := len(s.kernel.Scripts)
	if err := s.daemon.Reconcile(s.ctx); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if n := s.scriptsSince(mark); n != 0 {
		t.Fatalf("second reconcile issued %d kernel script(s), want 0 (cache and kernel disagree)", n)
	}
}

// #592 — the allowlist mirror is written in the kernel's own spelling and
// a second reconcile does not churn (the /32 vs bare-address mismatch
// stripped the admin's address on every odd sync).
func TestBanLifecycle_AllowlistMirrorSpellingIsStable(t *testing.T) {
	s := start(t, options{armed: true, allowlist: []string{"192.0.2.10/32", "2001:db8::/64"}})
	if got := s.kernel.Elements("allowed"); !contains(got, "192.0.2.10") || contains(got, "192.0.2.10/32") {
		t.Fatalf("@allowed = %v, want the bare address", got)
	}
	if got := s.kernel.Elements("allowed6"); !contains(got, "2001:db8::/64") {
		t.Fatalf("@allowed6 = %v, want the /64", got)
	}
	mark := len(s.kernel.Scripts)
	if err := s.daemon.ReconcileAllowlist(s.ctx); err != nil {
		t.Fatal(err)
	}
	if n := s.scriptsSince(mark); n != 0 {
		t.Fatalf("allowlist reconcile issued %d kernel script(s) on an already-correct set, want 0", n)
	}
}

// #583 — the engine (narrowed under ADR-0013) bans a socket-holding
// attacker the gate still sees as an ESTABLISHED peer: the ban is deferred,
// never applied while the peer is present, and applied with its remaining
// TTL once the peer is gone.
func TestBanLifecycle_GateRefusalIsDeferredNotLost(t *testing.T) {
	s := start(t, options{armed: true})
	attacker := netip.MustParseAddr("203.0.113.45")
	s.gate.set(attacker) // kernel view: connection held; engine view: unauthenticated → bannable

	s.sshBurst(attacker, 6)
	if _, ok := s.lastAction(attacker, "ban"); !ok {
		t.Fatal("engine did not ban")
	}
	if contains(s.blocked(), attacker.String()) {
		t.Fatalf("gate applied a ban for a live peer — Hard Rule 1 broken")
	}
	// Retries while the peer holds on: still refused.
	s.clock.advance(5 * time.Second)
	s.daemon.RunDeferredOnce(s.ctx)
	if contains(s.blocked(), attacker.String()) {
		t.Fatalf("deferred retry applied the ban while the peer was still present")
	}
	// Peer gone: the next due retry applies the stored ban.
	s.gate.set()
	s.clock.advance(5 * time.Second)
	s.daemon.RunDeferredOnce(s.ctx)
	if !contains(s.blocked(), attacker.String()) {
		t.Fatalf("deferred ban never reached the kernel: %v", s.blocked())
	}
	if exp, _ := s.kernel.Expiry("blocked", attacker.String()); exp.Sub(s.clock.now()) > 5*time.Minute || exp.Sub(s.clock.now()) < 4*time.Minute {
		t.Fatalf("deferred ban TTL = %v, want the remaining ~4m50s", exp.Sub(s.clock.now()))
	}
}
