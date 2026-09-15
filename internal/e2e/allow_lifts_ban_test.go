// SPDX-License-Identifier: AGPL-3.0-only

package e2e

// Invariant B1 (the allowlist wins in every layer) — issue #608: a runtime
// `allow` must lift an existing ban everywhere the ban lives (store row,
// kernel element, reconcile desired state), not only stop new ones.

import (
	"net/netip"
	"testing"
)

func TestAllow_LiftsExistingBanEverywhere(t *testing.T) {
	s := start(t, options{armed: true})
	victim := netip.MustParseAddr("203.0.113.90")

	// Three bursts climb the ladder to strike 3 (24 h).
	for i := 0; i < 3; i++ {
		s.sshBurst(victim, 6)
		if _, ok := s.lastAction(victim, "ban"); !ok {
			t.Fatalf("burst %d produced no ban", i+1)
		}
		if i < 2 { // simulate expiry between strikes; keep the third ban live
			if err := s.store.Unban(s.ctx, victim); err != nil {
				t.Fatal(err)
			}
			if err := s.daemon.Reconcile(s.ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !contains(s.blocked(), victim.String()) {
		t.Fatalf("precondition: %s not in the kernel: %v", victim, s.blocked())
	}

	// The operator allows the address.
	if resp := s.daemon.Allow(s.ctx, victim.String(), "operator: shared office NAT", ""); !resp.OK {
		t.Fatalf("allow: %s", resp.Error)
	}

	if _, _, _, found, _ := s.store.GetBanInfo(s.ctx, victim); found {
		t.Fatalf("store still reports an active ban after allow")
	}
	if contains(s.blocked(), victim.String()) {
		t.Fatalf("kernel still blocks %s right after allow", victim)
	}
	if !contains(s.kernel.Elements("allowed"), victim.String()) {
		t.Fatalf("@allowed does not hold %s: %v", victim, s.kernel.Elements("allowed"))
	}
	// The reconcile must not bring the ban back, and must not churn.
	if err := s.daemon.Reconcile(s.ctx); err != nil {
		t.Fatal(err)
	}
	if contains(s.blocked(), victim.String()) {
		t.Fatalf("reconcile re-added the ban of an allowed address")
	}
	mark := len(s.kernel.Scripts)
	if err := s.daemon.Reconcile(s.ctx); err != nil {
		t.Fatal(err)
	}
	if n := s.scriptsSince(mark); n != 0 {
		t.Fatalf("second reconcile issued %d kernel script(s), want 0", n)
	}
	// The lift is audited as an unban.
	entries, err := s.store.ListAuditLog(s.ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, e := range entries {
		if e.Op == "unban" && e.IP == victim.String() {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("no unban audit row for the allowed address")
	}
	// New evidence from the allowed address is recorded, never banned.
	s.sshBurst(victim, 6)
	if a, ok := s.firstDecision(victim); ok {
		t.Fatalf("allowed address got a ban-band decision: %+v", a)
	}
}
