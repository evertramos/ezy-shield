// Package decision_test — dedicated anti-lockout gate tests (SECURITY-REVIEW §2).
//
// These tests assert the core safety invariant: the engine must never produce a
// real ban action for the active SSH session, an allowlisted IP, or any IP inside
// a CDN/admin CIDR — regardless of score. A regression here is a lock-out / outage
// class of bug.
package decision_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// cloudflareTestCIDR and cloudflareSampleIP represent a typical CDN IP range used
// in tests. We use documentation/TEST-NET addresses to avoid accidental matches on
// a real CI runner's SSH session.
const (
	cloudflareTestCIDR = "203.0.113.128/25" // TEST-NET-3 upper half, stands in for a CDN range
	cloudflareSampleIP = "203.0.113.200"
	adminIP            = "203.0.113.1"
	outsiderIP         = "198.51.100.5" // TEST-NET-2, genuinely unprotected
)

// antiLockoutPolicy returns an armed policy with the CDN and admin CIDRs configured.
func antiLockoutPolicy() *config.Policy {
	return &config.Policy{
		Armed:            true,
		BanThreshold:     70,
		ObserveThreshold: 40,
		MaxBansPerMinute: 30,
		Strikes:          config.DefaultStrikes,
		Allowlist:        []string{adminIP},
		AdminCIDRs:       []string{cloudflareTestCIDR},
	}
}

func banVerdict(ip netip.Addr) []sdk.Verdict {
	return []sdk.Verdict{{
		IP:       ip,
		Score:    100,
		Category: "bruteforce",
		Source:   "rules",
		Reason:   "anti-lockout test — max score",
	}}
}

// TestAntiLockout_ActiveSSHPeer_CannotBeBanned simulates the daemon trying to ban
// the administrator's own active SSH session. The engine must refuse and return
// Op="record" — never "ban" (SECURITY-REVIEW §2, AGENTS Hard Rule §1).
func TestAntiLockout_ActiveSSHPeer_CannotBeBanned(t *testing.T) {
	sshIP := "203.0.113.50 12345 22"
	peer := netip.MustParseAddr("203.0.113.50")

	// Engine created without peer in static allowlist (simulates session started
	// after daemon launch — the most important dynamic case).
	t.Setenv("SSH_CLIENT", "")
	pol := &config.Policy{
		Armed:            true,
		BanThreshold:     70,
		ObserveThreshold: 40,
		MaxBansPerMinute: 30,
		Strikes:          config.DefaultStrikes,
	}
	st := newMock(nil)
	eng := mustEngine(t, pol, st)

	// Now set SSH_CLIENT to simulate a live session that started after New().
	t.Setenv("SSH_CLIENT", sshIP)

	act, err := eng.Decide(context.Background(), banVerdict(peer))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op == "ban" {
		t.Errorf("anti-lockout FAILED: engine produced Op=ban for active SSH peer %s", peer)
	}
	if len(st.banned) > 0 {
		t.Errorf("anti-lockout FAILED: RecordStrike called %d time(s) for active SSH peer", len(st.banned))
	}
}

// TestAntiLockout_ActiveSSHPeer_StaticAllowlist verifies that an SSH peer present
// at daemon startup is protected via the static allowlist built in New().
func TestAntiLockout_ActiveSSHPeer_StaticAllowlist(t *testing.T) {
	peer := netip.MustParseAddr("203.0.113.51")
	t.Setenv("SSH_CLIENT", peer.String()+" 22222 22")

	st := newMock(nil)
	pol := &config.Policy{
		Armed: true, BanThreshold: 70, ObserveThreshold: 40,
		MaxBansPerMinute: 30, Strikes: config.DefaultStrikes,
	}
	eng := mustEngine(t, pol, st)

	act, err := eng.Decide(context.Background(), banVerdict(peer))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op == "ban" {
		t.Errorf("static allowlist anti-lockout FAILED: Op=ban for startup SSH peer %s", peer)
	}
	if len(st.banned) > 0 {
		t.Errorf("RecordStrike called for SSH peer present at startup")
	}
}

// TestAntiLockout_AllowlistedIP_CannotBeBanned asserts that an IP explicitly in the
// allowlist returns Op="record" regardless of score, and RecordStrike is never called.
func TestAntiLockout_AllowlistedIP_CannotBeBanned(t *testing.T) {
	target := netip.MustParseAddr(adminIP)

	st := newMock(nil)
	eng := mustEngine(t, antiLockoutPolicy(), st)

	act, err := eng.Decide(context.Background(), banVerdict(target))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "record" {
		t.Errorf("allowlisted IP got Op=%q, want record (score=100)", act.Op)
	}
	if len(st.banned) > 0 {
		t.Errorf("RecordStrike called %d time(s) for allowlisted IP — invariant broken", len(st.banned))
	}
}

// TestAntiLockout_CDNRange_CannotBeBanned verifies that an IP inside an AdminCIDR
// (standing in for a CDN range) is also protected. This guards against accidentally
// blocking a whole CDN's origin IPs.
func TestAntiLockout_CDNRange_CannotBeBanned(t *testing.T) {
	target := netip.MustParseAddr(cloudflareSampleIP)

	st := newMock(nil)
	eng := mustEngine(t, antiLockoutPolicy(), st)

	act, err := eng.Decide(context.Background(), banVerdict(target))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "record" {
		t.Errorf("CDN range IP %s got Op=%q, want record", target, act.Op)
	}
	if len(st.banned) > 0 {
		t.Errorf("RecordStrike called %d time(s) for CDN range IP — would have blocked a CDN", len(st.banned))
	}
}

// TestAntiLockout_CDNRange_MultipleIPs checks all IPs in the configured CIDR.
// We sample the first, middle, and last host in the /25.
func TestAntiLockout_CDNRange_MultipleIPs(t *testing.T) {
	samples := []string{
		"203.0.113.129", // first host
		"203.0.113.192", // middle
		"203.0.113.254", // last host
	}

	for _, s := range samples {
		t.Run(s, func(t *testing.T) {
			target := netip.MustParseAddr(s)
			st := newMock(nil)
			eng := mustEngine(t, antiLockoutPolicy(), st)

			act, err := eng.Decide(context.Background(), banVerdict(target))
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if act.Op != "record" {
				t.Errorf("CDN IP %s got Op=%q (score=100), want record", s, act.Op)
			}
			if len(st.banned) > 0 {
				t.Errorf("RecordStrike called for CDN IP %s — outage invariant broken", s)
			}
		})
	}
}

// TestAntiLockout_UnprotectedIP_CanBeBanned is the positive control: an IP that is
// NOT in the allowlist or SSH session must actually get banned. Without this check,
// a bug that blocks *all* bans would pass the anti-lockout tests.
func TestAntiLockout_UnprotectedIP_CanBeBanned(t *testing.T) {
	target := netip.MustParseAddr(outsiderIP)

	st := newMock(nil)
	eng := mustEngine(t, antiLockoutPolicy(), st)

	act, err := eng.Decide(context.Background(), banVerdict(target))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "ban" {
		t.Errorf("non-protected IP %s got Op=%q, want ban (score=100)", target, act.Op)
	}
	if len(st.banned) == 0 {
		t.Error("RecordStrike not called for non-protected IP — ban did not happen")
	}
}

// TestAntiLockout_DryRunNeverBans verifies that dry-run mode (Armed=false)
// never produces an enforceable action for any IP, including ones that are
// NOT allowlisted. Since ADR-0009 §5 the store write itself is allowed —
// dry-run records strikes and simulated bans — so the enforcement invariant
// is carried by the Op: every action and every recorded row from a dry-run
// engine MUST say "dry_ban", because the daemon dispatches enforcer calls
// only for Op=="ban" and enforcer syncs skip dry_run rows.
func TestAntiLockout_DryRunNeverBans(t *testing.T) {
	pol := antiLockoutPolicy()
	pol.Armed = false
	target := netip.MustParseAddr(outsiderIP)

	st := newMock(nil)
	eng := mustEngine(t, pol, st)

	act, err := eng.Decide(context.Background(), banVerdict(target))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "dry_ban" {
		t.Errorf("dry-run: got Op=%q, want dry_ban", act.Op)
	}
	for _, rec := range st.banned {
		if rec.Op != "dry_ban" {
			t.Errorf("dry-run: recorded Op=%q — enforcement invariant broken (only dry_ban rows may be written while armed=false)", rec.Op)
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.banDry[target.String()] {
		t.Error("dry-run: bans_active row not flagged dry_run — enforcer sync would enforce it")
	}
}

// TestAntiLockout_AllowlistAlwaysFirstRegardlessOfStrike confirms that even an IP
// with many existing strikes (e.g. erroneously accumulated) cannot be banned once
// allowlisted — the allowlist check always runs before strike retrieval.
func TestAntiLockout_AllowlistAlwaysFirstRegardlessOfStrike(t *testing.T) {
	target := netip.MustParseAddr(adminIP)

	// Pre-load 99 strikes — this IP would normally get a permanent ban.
	st := newMock(map[string]int{adminIP: 99})
	eng := mustEngine(t, antiLockoutPolicy(), st)

	act, err := eng.Decide(context.Background(), banVerdict(target))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "record" {
		t.Errorf("allowlisted IP with 99 strikes got Op=%q, want record", act.Op)
	}
	if len(st.banned) > 0 {
		t.Errorf("RecordStrike called despite allowlist — invariant broken at high strike count")
	}
}
