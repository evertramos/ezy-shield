// SPDX-License-Identifier: AGPL-3.0-only

package e2e

// Invariant C3 (a rule fires on exactly the events it claims), end to end.

import (
	"net/netip"
	"testing"
	"time"
)

// #610 — an attacker pacing one wp-login attempt every 5 minutes must be
// caught by the hourly tier (http_wp_probe_sustained, 10/1h) even though the
// aggregator is flushed every 10 minutes in between. On dev before the fix
// the flush used the LAST configured window (300 s) instead of the longest
// (3600 s), so the hourly rule could never see more than ~10 minutes.
func TestDetection_HourlyTierSurvivesFlush(t *testing.T) {
	s := start(t, options{armed: true})
	attacker := netip.MustParseAddr("203.0.113.77")

	for i := 0; i < 9; i++ {
		s.httpHit(attacker, "/wp-login.php")
		s.clock.advance(5 * time.Minute)
		if i%2 == 1 {
			s.daemon.FlushOnce(s.ctx) // the 10-minute flush tick
		}
	}
	// 45 minutes in, nine attempts so far, none inside any 60 s window.
	if a, ok := s.lastAction(attacker, "ban"); ok {
		t.Fatalf("banned early: %+v", a)
	}
	s.httpHit(attacker, "/wp-login.php") // the 10th within the hour
	ban, ok := s.lastAction(attacker, "ban")
	if !ok {
		t.Fatalf("10 wp-login attempts in 45 minutes produced no ban — the hourly tier lost its history to the flush")
	}
	if ban.Strike != 1 {
		t.Fatalf("ban = %+v, want strike 1", ban)
	}
	if !contains(s.blocked(), attacker.String()) {
		t.Fatalf("kernel blocked set = %v, want %s", s.blocked(), attacker)
	}
}
