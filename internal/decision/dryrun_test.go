package decision_test

// Tests for ADR-0009 §5 (issue #145): dry-run mirrors armed semantics.
// A dry_ban records its strike and a simulated ban (dry_run=1) so that
// suppression, escalation, and the rate-limit cap behave exactly as an
// armed daemon would — while nothing is ever handed to an enforcer and
// the ban_ineffective diagnostic stays armed-only.

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// dryRunPolicy returns armedPolicy with Armed=false — everything else
// identical, which is the point: the two modes must differ only in
// enforcement.
func dryRunPolicy() *config.Policy {
	p := armedPolicy()
	p.Armed = false
	return p
}

func TestDryRun_RecordsStrikeAndSimulatedBan(t *testing.T) {
	t.Parallel()
	st := newMock(nil)
	e := mustEngine(t, dryRunPolicy(), st)

	act, err := e.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 90, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "dry_ban" {
		t.Fatalf("Op = %q, want dry_ban", act.Op)
	}
	if act.Strike != 1 {
		t.Errorf("Strike = %d, want 1", act.Strike)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.banned) != 1 {
		t.Fatalf("RecordStrike calls = %d, want 1 — dry_ban must be recorded (ADR-0009 §5)", len(st.banned))
	}
	if st.banned[0].Op != "dry_ban" {
		t.Errorf("recorded Op = %q, want dry_ban", st.banned[0].Op)
	}
	if !st.banDry[ip1.String()] {
		t.Error("bans_active row not marked dry_run — a simulated ban must never look like a real one")
	}
}

func TestDryRun_SuppressesDuringSimulatedTTL(t *testing.T) {
	t.Parallel()
	st := newMock(nil)
	e := mustEngine(t, dryRunPolicy(), st)

	// Episode 1: dry ban recorded.
	if _, err := e.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 90, "bruteforce")}); err != nil {
		t.Fatalf("Decide #1: %v", err)
	}
	// Re-hits during the simulated TTL: suppressed, no new strikes.
	for i := 0; i < 3; i++ {
		act, err := e.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 95, "bruteforce")})
		if err != nil {
			t.Fatalf("Decide re-hit %d: %v", i, err)
		}
		if act.Op != "already_banned" {
			t.Fatalf("re-hit %d: Op = %q, want already_banned (suppression must mirror armed)", i, act.Op)
		}
		if !strings.Contains(act.Reason, "simulated") {
			t.Errorf("re-hit %d: Reason = %q — should identify the ban as simulated", i, act.Reason)
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if got := st.strikes[ip1.String()]; got != 1 {
		t.Errorf("strike count after re-hits = %d, want 1 — one episode, one strike", got)
	}
	if got := st.supTotal[ip1.String()]; got != 3 {
		t.Errorf("suppressed_total = %d, want 3 — counters must still be recorded for observability", got)
	}
}

func TestDryRun_BanIneffectiveNeverFires(t *testing.T) {
	// Not parallel: captures the default slog logger.
	logs := captureLogs(t)
	st := newMock(nil)
	e := mustEngine(t, dryRunPolicy(), st)

	// Active simulated ban whose grace period has long passed.
	st.setSimulatedBan(ip1, 1)
	st.mu.Lock()
	st.banBannedAt[ip1.String()] = time.Now().Add(-time.Hour)
	st.mu.Unlock()

	// Far more post-grace events than BanIneffectiveMinEvents.
	for i := 0; i < 10; i++ {
		if _, err := e.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 95, "bruteforce")}); err != nil {
			t.Fatalf("Decide %d: %v", i, err)
		}
	}

	st.mu.Lock()
	fired := st.supFired[ip1.String()]
	st.mu.Unlock()
	if fired {
		t.Error("MarkBanIneffective fired in dry-run — ADR-0009 §5 says armed-only")
	}
	if strings.Contains(logs.String(), "ban_ineffective") {
		t.Errorf("ban_ineffective diagnostic logged in dry-run; logs:\n%s", logs.String())
	}
}

func TestDryRun_RateLimitMirrorsArmed(t *testing.T) {
	t.Parallel()
	pol := dryRunPolicy()
	pol.MaxBansPerMinute = 2
	st := newMock(nil)
	e := mustEngine(t, pol, st)

	ips := []netip.Addr{ip1, ip2, ip3}
	var rateLimited bool
	for _, ip := range ips {
		_, err := e.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip, 90, "scanner")})
		if errors.Is(err, decision.ErrRateLimited) {
			rateLimited = true
			continue
		}
		if err != nil {
			t.Fatalf("Decide %s: %v", ip, err)
		}
	}
	if !rateLimited {
		t.Error("third dry_ban did not hit max_bans_per_minute — dry-run must mirror the cap")
	}
}

func TestArmed_IgnoresSimulatedBan_RecordsRealBan(t *testing.T) {
	t.Parallel()
	st := newMock(map[string]int{ip1.String(): 1})
	// Leftover simulated ban from before the operator armed the daemon.
	st.setSimulatedBan(ip1, 1)
	e := mustEngine(t, armedPolicy(), st)

	act, err := e.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 90, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "ban" {
		t.Fatalf("Op = %q, want ban — a simulated ban must not suppress real sentencing (nothing enforces it)", act.Op)
	}
	if act.Strike != 2 {
		t.Errorf("Strike = %d, want 2 — dry-run strike history carries into armed mode", act.Strike)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if st.banDry[ip1.String()] {
		t.Error("bans_active row still dry_run after real strike — upsert must overwrite the flag")
	}
}

// TestDryRun_EscalationParity runs the same scripted attack (offend → ban
// expires → re-offend, up the whole ladder) through an armed engine and a
// dry-run engine, and asserts the sentencing sequence — strike numbers and
// TTLs — is identical rung for rung (ADR-0009 §5: dry-run shows exactly the
// escalation production would apply).
func TestDryRun_EscalationParity(t *testing.T) {
	t.Parallel()

	run := func(pol *config.Policy) (strikes []int, ttls []time.Duration) {
		st := newMock(nil)
		e := mustEngine(t, pol, st)
		episodes := len(pol.Strikes) + 1 // walk past the top rung to check clamping
		for i := 0; i < episodes; i++ {
			act, err := e.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 90, "bruteforce")})
			if err != nil {
				t.Fatalf("episode %d: %v", i, err)
			}
			strikes = append(strikes, act.Strike)
			ttls = append(ttls, act.TTL)
			// Simulate the ban (real or simulated) expiring before the next
			// episode; the last strike stays recent so the escalation
			// exemption applies identically in both modes.
			st.setBanned(ip1, false)
			st.setLastStrike(ip1, time.Now().Add(-time.Minute), time.Second)
		}
		return strikes, ttls
	}

	armedStrikes, armedTTLs := run(armedPolicy())
	dryStrikes, dryTTLs := run(dryRunPolicy())

	if len(armedStrikes) != len(dryStrikes) {
		t.Fatalf("episode counts differ: armed %d, dry %d", len(armedStrikes), len(dryStrikes))
	}
	for i := range armedStrikes {
		if armedStrikes[i] != dryStrikes[i] {
			t.Errorf("episode %d: strike armed=%d dry=%d — ladders diverged", i, armedStrikes[i], dryStrikes[i])
		}
		if armedTTLs[i] != dryTTLs[i] {
			t.Errorf("episode %d: ttl armed=%s dry=%s — ladders diverged", i, armedTTLs[i], dryTTLs[i])
		}
	}
}
