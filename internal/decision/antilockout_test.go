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
	"github.com/evertramos/ezy-shield/internal/decision"
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

// ── IPv4-mapped IPv6 forms (issue #314) ─────────────────────────────────────
// Go's netip treats "::ffff:a.b.c.d" as distinct from "a.b.c.d": prefix
// Contains and == both fail across forms. Dual-stack sshd/nginx listeners log
// the mapped form, and the parsers deliver it verbatim — so every protection
// below must normalize (Unmap) or a mapped verdict bypasses the decision
// layer entirely and records strikes/ban rows against a protected address.

// TestAntiLockout_MappedVerdictIP_CannotBypassAllowlist: a mapped form of an
// allowlisted / admin-CIDR address must be treated exactly like the plain form.
func TestAntiLockout_MappedVerdictIP_CannotBypassAllowlist(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"mapped allowlisted admin IP", "::ffff:" + adminIP},
		{"mapped IP inside admin/CDN CIDR", "::ffff:" + cloudflareSampleIP},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := netip.MustParseAddr(tc.ip)
			st := newMock(nil)
			eng := mustEngine(t, antiLockoutPolicy(), st)

			act, err := eng.Decide(context.Background(), banVerdict(target))
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if act.Op != "record" {
				t.Errorf("mapped form %s got Op=%q, want record (allowlist bypassed — issue #314)", tc.ip, act.Op)
			}
			if len(st.banned) > 0 {
				t.Errorf("RecordStrike called %d time(s) for mapped form of protected IP", len(st.banned))
			}
		})
	}
}

// TestAntiLockout_MappedVerdictIP_ActiveSSHPeer: kernel-derived peers are
// already unmapped (sshpeers.go), so a mapped verdict IP must still hit the
// peer equality check.
func TestAntiLockout_MappedVerdictIP_ActiveSSHPeer(t *testing.T) {
	t.Setenv("SSH_CLIENT", "")
	pol := &config.Policy{
		Armed: true, BanThreshold: 70, ObserveThreshold: 40,
		MaxBansPerMinute: 30, Strikes: config.DefaultStrikes,
	}
	st := newMock(nil)
	eng := mustEngine(t, pol, st)
	eng.SetSSHPeerProbe(func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("203.0.113.50")}
	})

	act, err := eng.Decide(context.Background(), banVerdict(netip.MustParseAddr("::ffff:203.0.113.50")))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op == "ban" || len(st.banned) > 0 {
		t.Errorf("mapped form of active SSH peer got Op=%q (%d strikes recorded) — anti-lockout bypassed (issue #314)",
			act.Op, len(st.banned))
	}
}

// TestAntiLockout_MappedSSHClient_PlainVerdict: the reverse direction — a
// dual-stack sshd exports SSH_CLIENT with the mapped form while the verdict
// carries the plain IPv4. Both the startup allowlist entry (buildAllowlist)
// and the per-call SSH_CLIENT peer check must normalize.
func TestAntiLockout_MappedSSHClient_PlainVerdict(t *testing.T) {
	t.Setenv("SSH_CLIENT", "::ffff:203.0.113.52 12345 22")
	pol := &config.Policy{
		Armed: true, BanThreshold: 70, ObserveThreshold: 40,
		MaxBansPerMinute: 30, Strikes: config.DefaultStrikes,
	}
	st := newMock(nil)
	eng := mustEngine(t, pol, st)
	eng.SetSSHPeerProbe(func() []netip.Addr { return nil }) // isolate the SSH_CLIENT path

	act, err := eng.Decide(context.Background(), banVerdict(netip.MustParseAddr("203.0.113.52")))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op == "ban" || len(st.banned) > 0 {
		t.Errorf("plain verdict for mapped SSH_CLIENT peer got Op=%q (%d strikes recorded) — issue #314",
			act.Op, len(st.banned))
	}
}

// TestAntiLockout_MappedAllowlistConfigEntries: operators on dual-stack hosts
// may copy the mapped form straight from a log into policy allowlist entries;
// both bare-IP and CIDR entries must protect the plain form.
func TestAntiLockout_MappedAllowlistConfigEntries(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		ip    string
	}{
		{"mapped bare IP entry", "::ffff:203.0.113.77", "203.0.113.77"},
		{"mapped CIDR entry", "::ffff:203.0.113.0/120", "203.0.113.9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pol := &config.Policy{
				Armed: true, BanThreshold: 70, ObserveThreshold: 40,
				MaxBansPerMinute: 30, Strikes: config.DefaultStrikes,
				Allowlist: []string{tc.entry},
			}
			st := newMock(nil)
			eng := mustEngine(t, pol, st)

			act, err := eng.Decide(context.Background(), banVerdict(netip.MustParseAddr(tc.ip)))
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if act.Op != "record" || len(st.banned) > 0 {
				t.Errorf("allowlist entry %q did not protect %s: Op=%q, %d strikes (issue #314)",
					tc.entry, tc.ip, act.Op, len(st.banned))
			}
		})
	}
}

// ── Fast-reconnect burst behind the SSH-peer shield (issue #420) ────────────
// A bruteforcer that reconnects faster than the peer-cache TTL keeps an
// ESTABLISHED connection visible at every evaluation, so every attempt in its
// threshold window is refused by the anti-lockout — correctly. The fix is a
// daemon-side deferred re-evaluation after the connection closes; these tests
// pin down the engine-side contract that re-evaluation relies on. They ADD
// cases — the refusal invariant above is untouched.

// TestAntiLockout_SSHPeerRefusal_ReasonIsStableContract: the daemon keys the
// deferred re-check on the exact refusal reason. If this constant drifts from
// what Decide emits, the re-check silently never schedules and the #420 gap
// reopens — so the coupling is pinned here.
func TestAntiLockout_SSHPeerRefusal_ReasonIsStableContract(t *testing.T) {
	t.Setenv("SSH_CLIENT", "")
	peer := netip.MustParseAddr("198.51.100.20")
	pol := &config.Policy{
		Armed: true, BanThreshold: 70, ObserveThreshold: 40,
		MaxBansPerMinute: 30, Strikes: config.DefaultStrikes,
	}
	st := newMock(nil)
	eng := mustEngine(t, pol, st)
	eng.SetSSHPeerProbe(func() []netip.Addr { return []netip.Addr{peer} })

	act, err := eng.Decide(context.Background(), banVerdict(peer))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "record" || act.Reason != decision.ReasonAntiLockoutSSHPeer {
		t.Errorf("refusal = Op=%q Reason=%q, want Op=record Reason=%q",
			act.Op, act.Reason, decision.ReasonAntiLockoutSSHPeer)
	}
	if len(st.banned) > 0 {
		t.Errorf("RecordStrike called %d time(s) for active SSH peer", len(st.banned))
	}
}

// TestAntiLockout_SSHPeerProtection_IsConnectionScoped: while the connection
// is ESTABLISHED every evaluation refuses; once the kernel no longer reports
// the peer, the very next evaluation of the same still-in-window evidence
// bans. This is the engine-side foundation of the deferred re-check: the
// shield protects a connection, not an address forever.
func TestAntiLockout_SSHPeerProtection_IsConnectionScoped(t *testing.T) {
	t.Setenv("SSH_CLIENT", "")
	attacker := netip.MustParseAddr("198.51.100.21")
	pol := &config.Policy{
		Armed: true, BanThreshold: 70, ObserveThreshold: 40,
		MaxBansPerMinute: 30, Strikes: config.DefaultStrikes,
	}
	st := newMock(nil)
	eng := mustEngine(t, pol, st)

	// Burst phase: every evaluation sees an ESTABLISHED connection.
	eng.SetSSHPeerProbe(func() []netip.Addr { return []netip.Addr{attacker} })
	for i := 0; i < 5; i++ {
		act, err := eng.Decide(context.Background(), banVerdict(attacker))
		if err != nil {
			t.Fatalf("Decide (burst %d): %v", i, err)
		}
		if act.Op != "record" || act.Reason != decision.ReasonAntiLockoutSSHPeer {
			t.Fatalf("burst evaluation %d: Op=%q Reason=%q, want anti-lockout refusal", i, act.Op, act.Reason)
		}
	}
	if len(st.banned) > 0 {
		t.Fatalf("RecordStrike called during burst — refusal invariant broken")
	}

	// Connection closed: the kernel reports no peer. SetSSHPeerProbe resets
	// the TTL cache, standing in for the ≥2×TTL delay the daemon waits.
	eng.SetSSHPeerProbe(func() []netip.Addr { return nil })
	act, err := eng.Decide(context.Background(), banVerdict(attacker))
	if err != nil {
		t.Fatalf("Decide (post-close): %v", err)
	}
	if act.Op != "ban" {
		t.Errorf("post-close re-evaluation: Op=%q, want ban (issue #420 gap)", act.Op)
	}
	if len(st.banned) != 1 {
		t.Errorf("RecordStrike calls = %d, want exactly 1", len(st.banned))
	}
}

// TestAntiLockout_SSHPeerStillConnected_RepeatedReevaluationNeverBans is the
// operator scenario for the deferred re-check: however many times the same
// evidence is re-evaluated, a peer the kernel still reports as ESTABLISHED is
// never banned. The re-check must not weaken this by even one iteration.
func TestAntiLockout_SSHPeerStillConnected_RepeatedReevaluationNeverBans(t *testing.T) {
	t.Setenv("SSH_CLIENT", "")
	operator := netip.MustParseAddr("198.51.100.22")
	pol := &config.Policy{
		Armed: true, BanThreshold: 70, ObserveThreshold: 40,
		MaxBansPerMinute: 30, Strikes: config.DefaultStrikes,
	}
	st := newMock(nil)
	eng := mustEngine(t, pol, st)
	eng.SetSSHPeerProbe(func() []netip.Addr { return []netip.Addr{operator} })

	for i := 0; i < 20; i++ {
		act, err := eng.Decide(context.Background(), banVerdict(operator))
		if err != nil {
			t.Fatalf("Decide (re-eval %d): %v", i, err)
		}
		if act.Op == "ban" {
			t.Fatalf("re-evaluation %d banned a still-connected SSH peer", i)
		}
	}
	if len(st.banned) > 0 {
		t.Errorf("RecordStrike called %d time(s) for still-connected peer", len(st.banned))
	}
}

// TestDecide_MappedVerdictIP_NormalizedInAction: an UNPROTECTED mapped IP must
// still be banned (normalization closes the bypass without opening a pass) and
// the Action must carry the unmapped form — store rows then key the canonical
// address (no split offender identity) and the enforcer receives an IPv4 the
// v4 set can actually match on the wire.
func TestDecide_MappedVerdictIP_NormalizedInAction(t *testing.T) {
	target := netip.MustParseAddr("::ffff:" + outsiderIP)
	st := newMock(nil)
	eng := mustEngine(t, antiLockoutPolicy(), st)

	act, err := eng.Decide(context.Background(), banVerdict(target))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	wantIP := netip.MustParseAddr(outsiderIP)
	if act.Op != "ban" {
		t.Errorf("mapped unprotected IP got Op=%q, want ban", act.Op)
	}
	if act.IP != wantIP {
		t.Errorf("Action.IP = %v, want unmapped %v", act.IP, wantIP)
	}
	if len(st.banned) != 1 || st.banned[0].IP != wantIP {
		t.Errorf("RecordStrike actions = %+v, want exactly one keyed by %v", st.banned, wantIP)
	}
}
