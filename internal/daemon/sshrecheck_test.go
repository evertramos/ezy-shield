// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// waitFor polls cond up to timeout, returning true once it holds.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// newRecheckDaemon builds an armed daemon whose SSH-peer probe is driven by
// peers(). Delay/tick are short so the deferred re-check fires quickly in
// tests. The pipeline is not started; tests drive it directly.
func newRecheckDaemon(t *testing.T, enf *fakeEnforcer, peers func() []netip.Addr) (*Daemon, *store.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	policy := &config.Policy{
		Armed:            true,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}
	d, err := New(Config{
		Policy:          policy,
		Store:           db,
		Parsers:         []sdk.Parser{parser.NewSSHParser(slog.Default())},
		Enforcer:        enf,
		SocketPath:      "",
		MaxIPs:          100,
		SSHRecheckDelay: 20 * time.Millisecond,
		SSHRecheckTick:  5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.decEng.SetSSHPeerProbe(peers)
	return d, db
}

// feedBurst pushes n SSH failures for ip through the pipeline exactly as
// processRaw would, so aggregates + verdicts + Decide + the re-check schedule
// all run. Each attempt sees whatever the peer probe currently reports.
func feedBurst(ctx context.Context, d *Daemon, ip netip.Addr, n int) {
	for _, raw := range bruteforceLines(ip, n) {
		d.processRaw(ctx, raw)
	}
}

// TestSSHRecheck_FastReconnectBurst_BannedAfterConnectionCloses is the core
// issue #420 regression: a burst whose every attempt is refused because an
// ESTABLISHED peer is visible must be banned by the deferred re-check once
// the connection closes — from the still-in-window evidence.
func TestSSHRecheck_FastReconnectBurst_BannedAfterConnectionCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attacker := netip.MustParseAddr("192.0.2.77")
	established := true // attacker holds a fast-reconnecting connection
	probe := func() []netip.Addr {
		if established {
			return []netip.Addr{attacker}
		}
		return nil
	}
	enf := &fakeEnforcer{}
	d, _ := newRecheckDaemon(t, enf, probe)

	go d.runSSHRecheck(ctx)

	// Burst: 6 failures, each refused by the anti-lockout (peer established).
	feedBurst(ctx, d, attacker, 6)
	if enf.BanCount() != 0 {
		t.Fatalf("enforcer banned during burst: %d — refusal invariant broken", enf.BanCount())
	}
	if d.sshRecheck.len() == 0 {
		t.Fatal("no deferred re-check armed after suppressed would-be ban")
	}

	// Connection closes. In production the ≥2×TTL delay guarantees the
	// re-check reads a fresh /proc probe (never the cache that justified the
	// refusal); re-setting the probe busts the engine's 2s peer cache the
	// same way, keeping the test fast without weakening what it proves.
	established = false
	d.decEng.SetSSHPeerProbe(probe)
	if !waitFor(2*time.Second, func() bool { return enf.BanCount() > 0 }) {
		t.Fatalf("attacker not banned within deferred window after connection closed")
	}
	if got := enf.bans[0].IP; got != attacker {
		t.Errorf("banned IP = %v, want %v", got, attacker)
	}
}

// TestSSHRecheck_OperatorStillConnected_NeverBanned is the anti-lockout
// invariant under the deferred re-check: a peer that stays ESTABLISHED across
// every re-check (a real operator session) is never banned, even though its
// event history crossed the threshold. The re-check re-arms, bounded.
func TestSSHRecheck_OperatorStillConnected_NeverBanned(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	operator := netip.MustParseAddr("192.0.2.88")
	enf := &fakeEnforcer{}
	// The peer is ALWAYS established — the operator never disconnects.
	d, _ := newRecheckDaemon(t, enf, func() []netip.Addr {
		return []netip.Addr{operator}
	})

	go d.runSSHRecheck(ctx)

	feedBurst(ctx, d, operator, 6)

	// Give the re-check several delay windows to (wrongly) fire. It must not.
	time.Sleep(300 * time.Millisecond)
	if enf.BanCount() != 0 {
		t.Fatalf("operator with active SSH session was banned %d time(s) — anti-lockout invariant broken", enf.BanCount())
	}
}

// TestSSHRecheck_EvidenceAgedOut_NoBan: if the connection closes only after
// the burst has slid out of every rule window, the re-check finds no verdicts
// and bans nothing (no phantom ban from stale scheduling).
func TestSSHRecheck_EvidenceAgedOut_NoBan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attacker := netip.MustParseAddr("192.0.2.99")
	enf := &fakeEnforcer{}
	d, _ := newRecheckDaemon(t, enf, func() []netip.Addr { return nil })

	// Manually arm a re-check for an IP with no current aggregates (evidence
	// already aged out). The re-check must decline to ban.
	d.sshRecheck.schedule(attacker, time.Now(), nil)
	go d.runSSHRecheck(ctx)

	if !waitFor(500*time.Millisecond, func() bool { return d.sshRecheck.len() == 0 }) {
		t.Fatal("re-check entry not consumed")
	}
	time.Sleep(50 * time.Millisecond)
	if enf.BanCount() != 0 {
		t.Errorf("banned %d IP(s) with no in-window evidence — phantom ban", enf.BanCount())
	}
}

// TestSSHRecheck_NoDoubleBan: once the deferred re-check bans the IP, a
// second re-check (or a late duplicate) must not produce a second strike —
// the active-ban guard in Decide suppresses it (Op=already_banned), which the
// re-check does not re-arm.
func TestSSHRecheck_NoDoubleBan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attacker := netip.MustParseAddr("192.0.2.111")
	enf := &fakeEnforcer{}
	d, _ := newRecheckDaemon(t, enf, func() []netip.Addr { return nil })

	go d.runSSHRecheck(ctx)

	// Burst with no peer visible → banned immediately by the pipeline.
	feedBurst(ctx, d, attacker, 6)
	if !waitFor(time.Second, func() bool { return enf.BanCount() >= 1 }) {
		t.Fatal("attacker not banned by the pipeline")
	}
	first := enf.BanCount()

	// Arm a stray re-check for the now-banned IP; it must not add a strike.
	d.sshRecheck.schedule(attacker, time.Now(), nil)
	if !waitFor(500*time.Millisecond, func() bool { return d.sshRecheck.len() == 0 }) {
		t.Fatal("stray re-check not consumed")
	}
	time.Sleep(50 * time.Millisecond)
	if enf.BanCount() != first {
		t.Errorf("re-check produced an extra enforcer ban for an already-banned IP: %d → %d",
			first, enf.BanCount())
	}
}

// TestSSHRecheckQueue_ScheduleRequeueBudget unit-tests the queue's re-arm
// budget and dedup semantics without a running daemon.
// TestSSHRecheck_AIElevatedBan_ReplayedOnRecheck is the issue #442
// regression: when the original would-be ban existed only because an AI
// verdict pushed a rules-only ambiguous score over ban_threshold, the
// deferred re-check must reproduce that ban once the SSH peer is gone —
// previously it re-derived rules only, got notify_only, and silently
// dropped the entry.
func TestSSHRecheck_AIElevatedBan_ReplayedOnRecheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attacker := netip.MustParseAddr("192.0.2.77")
	enf := &fakeEnforcer{}
	d, _ := newRecheckDaemon(t, enf, func() []netip.Addr { return nil })
	// Raise the ban threshold above ssh_bruteforce's rule score (85) so the
	// rule evidence alone lands in the ambiguous band — the shape where only
	// the AI push reaches a ban.
	d.policy.BanThreshold = 90

	// In-window rule evidence exists (peer was present during the burst, so
	// nothing was banned — scores stayed sub-threshold anyway).
	feedBurst(ctx, d, attacker, 6)

	// The pipeline's refusal, as it would look with AI enabled: rule verdict
	// 85 + ai verdict 95 ≥ threshold tripping anti-lockout.
	aiV := sdk.Verdict{IP: attacker, Score: 95, Category: "bruteforce",
		Confidence: 0.9, Reason: "ai judged hostile", Source: "ai:test"}
	refusal := sdk.Action{IP: attacker, Op: "record", Reason: decision.ReasonAntiLockoutSSHPeer}
	d.maybeScheduleSSHRecheck(ctx, refusal, []sdk.Verdict{
		{IP: attacker, Score: 85, Source: "rule/ssh_bruteforce"},
		aiV,
	})
	if d.sshRecheck.len() != 1 {
		t.Fatal("re-check not armed for the AI-elevated refusal")
	}

	go d.runSSHRecheck(ctx)

	// Peer gone (probe returns nil from the start): the deferred pass must
	// ban from live rule evidence + the replayed AI verdict.
	if !waitFor(time.Second, func() bool { return enf.BanCount() >= 1 }) {
		t.Fatal("AI-elevated ban was not reproduced by the deferred re-check (issue #442)")
	}
}

// TestSSHRecheck_AIElevated_PeerStillThere_NeverBanned: the replayed AI
// verdict must not weaken the anti-lockout invariant — with the peer still
// ESTABLISHED the re-check keeps refusing.
func TestSSHRecheck_AIElevated_PeerStillThere_NeverBanned(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attacker := netip.MustParseAddr("192.0.2.78")
	enf := &fakeEnforcer{}
	d, _ := newRecheckDaemon(t, enf, func() []netip.Addr { return []netip.Addr{attacker} })
	d.policy.BanThreshold = 90

	feedBurst(ctx, d, attacker, 6)
	aiV := sdk.Verdict{IP: attacker, Score: 95, Source: "ai:test"}
	d.maybeScheduleSSHRecheck(ctx, sdk.Action{IP: attacker, Op: "record",
		Reason: decision.ReasonAntiLockoutSSHPeer},
		[]sdk.Verdict{{IP: attacker, Score: 85, Source: "rule/ssh_bruteforce"}, aiV})

	go d.runSSHRecheck(ctx)
	time.Sleep(150 * time.Millisecond) // several re-check rounds
	if enf.BanCount() != 0 {
		t.Fatalf("banned an IP with a live ESTABLISHED SSH peer — anti-lockout invariant broken")
	}
}

// TestElevatedAIVerdict pins the capture rule: carried only when the ban
// NEEDED the AI push.
func TestElevatedAIVerdict(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.5")
	rule80 := sdk.Verdict{IP: ip, Score: 80, Source: "rule/ssh_bruteforce"}
	rule95 := sdk.Verdict{IP: ip, Score: 95, Source: "rule/ssh_bruteforce"}
	ai92 := sdk.Verdict{IP: ip, Score: 92, Source: "ai:anthropic"}
	ai97 := sdk.Verdict{IP: ip, Score: 97, Source: "ai:openai"}

	if got := elevatedAIVerdict([]sdk.Verdict{rule80, ai92}, 90); got == nil || got.Score != 92 {
		t.Errorf("ambiguous rules + elevating AI: got %+v, want the ai:92 verdict", got)
	}
	if got := elevatedAIVerdict([]sdk.Verdict{rule80, ai92, ai97}, 90); got == nil || got.Score != 97 {
		t.Errorf("two AI verdicts: got %+v, want the highest (97)", got)
	}
	if got := elevatedAIVerdict([]sdk.Verdict{rule95, ai97}, 90); got != nil {
		t.Errorf("rules alone over threshold: got %+v, want nil (no replay needed)", got)
	}
	if got := elevatedAIVerdict([]sdk.Verdict{rule80}, 90); got != nil {
		t.Errorf("no AI verdict: got %+v, want nil", got)
	}
	if got := elevatedAIVerdict([]sdk.Verdict{rule80, {IP: ip, Score: 85, Source: "ai:x"}}, 90); got != nil {
		t.Errorf("AI below threshold: got %+v, want nil", got)
	}
}

func TestSSHRecheckQueue_ScheduleRequeueBudget(t *testing.T) {
	var q sshRecheckQueue
	ip := netip.MustParseAddr("198.51.100.1")

	if !q.schedule(ip, time.Now().Add(-time.Second), nil) {
		t.Fatal("schedule returned false on empty queue")
	}
	if q.len() != 1 {
		t.Fatalf("len = %d, want 1", q.len())
	}
	// Due immediately.
	due := q.due(time.Now())
	if len(due) != 1 || due[0].ip != ip || due[0].attempts != 0 {
		t.Fatalf("due = %+v, want one entry for %v attempts 0", due, ip)
	}
	if q.len() != 0 {
		t.Fatalf("len after due = %d, want 0", q.len())
	}

	// requeue honors the attempt budget: at the cap it refuses.
	if q.requeue(ip, sshRecheckMaxAttempts, time.Now(), nil) {
		t.Error("requeue returned true at the attempt cap — retry budget not enforced")
	}
	if q.len() != 0 {
		t.Errorf("len = %d after refused requeue, want 0", q.len())
	}
	// Below the cap it re-arms carrying the spent-attempt count.
	if !q.requeue(ip, 3, time.Now().Add(-time.Second), nil) {
		t.Fatal("requeue below cap returned false")
	}
	due = q.due(time.Now())
	if len(due) != 1 || due[0].attempts != 3 {
		t.Fatalf("requeued due = %+v, want attempts 3", due)
	}
}
