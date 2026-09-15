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

// #621 — evidence that earned a strike is consumed by it. After the 5-minute
// strike-1 ban expires, a benign request must not turn the same hour of
// wp-login hits into strike 2; only NEW threshold-crossing evidence may.
func TestDecision_NoSecondStrikeOnSameEvidence(t *testing.T) {
	s := start(t, options{armed: true})
	attacker := netip.MustParseAddr("203.0.113.78")

	for i := 0; i < 10; i++ { // 10 hits in 45 min → hourly tier fires
		s.httpHit(attacker, "/wp-login.php")
		s.clock.advance(5 * time.Minute)
	}
	first, ok := s.lastAction(attacker, "ban")
	if !ok || first.Strike != 1 {
		t.Fatalf("no strike-1 ban: %+v ok=%v", first, ok)
	}
	// Ban over (5 min TTL), reaper ran, attacker (or anyone at that IP)
	// loads the home page once.
	s.clock.advance(6 * time.Minute)
	if _, err := s.daemon.ExpireOnce(s.ctx); err != nil {
		t.Fatal(err)
	}
	s.httpHit(attacker, "/")
	if a, ok := s.lastAction(attacker, "ban"); ok {
		t.Fatalf("a benign request after the ban expired earned strike %d from evidence already consumed by strike 1: %+v", a.Strike, a)
	}
	// Ten NEW hits inside the hour: that is fresh evidence → strike 2.
	for i := 0; i < 10; i++ {
		s.httpHit(attacker, "/wp-login.php")
		s.clock.advance(time.Minute)
	}
	second, ok := s.lastAction(attacker, "ban")
	if !ok || second.Strike != 2 {
		t.Fatalf("fresh evidence did not earn strike 2: %+v ok=%v", second, ok)
	}
}

// #636 — the persistent long-window counters must also treat evidence as
// consumed by the strike it earned: after the strike-1 ban expires, ONE
// more failure must not become strike 2 (ssh_bruteforce_daily, 5/24h);
// five new failures must.
func TestDecision_LongWindowNoSecondStrikeOnSameEvidence(t *testing.T) {
	s := start(t, options{armed: true})
	attacker := netip.MustParseAddr("203.0.113.79")

	for i := 0; i < 5; i++ { // five failures 30 min apart → daily tier fires on the 5th
		s.sshBurst(attacker, 1)
		if i < 4 {
			s.clock.advance(30 * time.Minute)
		}
	}
	first, ok := s.lastAction(attacker, "ban")
	if !ok || first.Strike != 1 {
		t.Fatalf("no strike-1 ban from the daily tier: %+v ok=%v", first, ok)
	}
	s.clock.advance(6 * time.Minute)
	if _, err := s.daemon.ExpireOnce(s.ctx); err != nil {
		t.Fatal(err)
	}
	s.sshBurst(attacker, 1) // one more failure — five old ones are still inside 24 h
	if a, ok := s.lastAction(attacker, "ban"); ok {
		t.Fatalf("one failure after the ban expired earned strike %d from evidence already consumed: %+v", a.Strike, a)
	}
	for i := 0; i < 5; i++ { // five NEW failures → strike 2
		s.clock.advance(30 * time.Minute)
		s.sshBurst(attacker, 1)
	}
	second, ok := s.lastAction(attacker, "ban")
	if !ok || second.Strike != 2 {
		t.Fatalf("fresh evidence did not earn strike 2: %+v ok=%v", second, ok)
	}
}
