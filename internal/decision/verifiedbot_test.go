package decision_test

// Tests for the verified-bot guard (issue #215): a forward-confirmed
// crawler is spared with an audited record; a failed verification (or no
// verifier at all) leaves the normal ban path untouched; the allowlist and
// anti-lockout checks still run FIRST.

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/decision"
)

func botGuardEngine(t *testing.T, st decision.Store, verify func(context.Context, netip.Addr) (string, bool)) *decision.Engine {
	t.Helper()
	pol := &config.Policy{
		Armed:            false,
		BanThreshold:     70,
		ObserveThreshold: 40,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}
	eng, err := decision.New(pol, st)
	if err != nil {
		t.Fatalf("decision.New: %v", err)
	}
	eng.SetSSHPeerProbe(func() []netip.Addr { return nil })
	if verify != nil {
		eng.SetBotVerifier(verify)
	}
	return eng
}

func TestDecide_VerifiedBotSpared(t *testing.T) {
	t.Parallel()
	st := newMock(nil)
	var asked netip.Addr
	eng := botGuardEngine(t, st, func(_ context.Context, ip netip.Addr) (string, bool) {
		asked = ip
		return "googlebot", true
	})

	ip := netip.MustParseAddr("192.0.2.40")
	act, err := eng.Decide(context.Background(), banVerdicts(ip))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "record" || !strings.HasPrefix(act.Reason, decision.ReasonVerifiedBotSpared) {
		t.Fatalf("verified bot must be spared, got Op=%q Reason=%q", act.Op, act.Reason)
	}
	if !strings.Contains(act.Reason, "googlebot") {
		t.Fatalf("spared reason must name the provider, got %q", act.Reason)
	}
	if asked != ip {
		t.Fatalf("verifier asked for %s, want %s", asked, ip)
	}
	if len(st.banned) != 0 {
		t.Fatal("spared bot must not be banned")
	}
	// The sparing itself is audited.
	var audited bool
	for _, a := range st.audited {
		if strings.HasPrefix(a.Reason, decision.ReasonVerifiedBotSpared) {
			audited = true
		}
	}
	if !audited {
		t.Fatal("verified-bot sparing must leave an audit entry")
	}
}

func TestDecide_FailedVerificationBansNormally(t *testing.T) {
	t.Parallel()
	st := newMock(nil)
	eng := botGuardEngine(t, st, func(_ context.Context, _ netip.Addr) (string, bool) {
		return "", false // spoofer: claim did not confirm
	})

	ip := netip.MustParseAddr("192.0.2.41")
	act, err := eng.Decide(context.Background(), banVerdicts(ip))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "dry_ban" {
		t.Fatalf("spoofer must proceed down the normal (dry-run) ban path, got %q", act.Op)
	}
}

func TestDecide_NoVerifierMeansNoChange(t *testing.T) {
	t.Parallel()
	st := newMock(nil)
	eng := botGuardEngine(t, st, nil)
	ip := netip.MustParseAddr("192.0.2.42")
	act, err := eng.Decide(context.Background(), banVerdicts(ip))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "dry_ban" {
		t.Fatalf("without a verifier the ban path is unchanged, got %q", act.Op)
	}
}

func TestDecide_VerifierNeverCalledBelowBanThreshold(t *testing.T) {
	t.Parallel()
	st := newMock(nil)
	called := false
	eng := botGuardEngine(t, st, func(_ context.Context, _ netip.Addr) (string, bool) {
		called = true
		return "googlebot", true
	})
	ip := netip.MustParseAddr("192.0.2.43")
	verdicts := banVerdicts(ip)
	verdicts[0].Score = 50 // observe band
	if _, err := eng.Decide(context.Background(), verdicts); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if called {
		t.Fatal("verifier must run only for ban candidates (never on record/notify paths)")
	}
}

func TestDecide_AllowlistStillWinsBeforeBotGuard(t *testing.T) {
	t.Parallel()
	st := newMock(nil)
	pol := &config.Policy{
		Armed:            false,
		BanThreshold:     70,
		ObserveThreshold: 40,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
		Allowlist:        []string{"192.0.2.44/32"},
	}
	eng, err := decision.New(pol, st)
	if err != nil {
		t.Fatalf("decision.New: %v", err)
	}
	eng.SetSSHPeerProbe(func() []netip.Addr { return nil })
	called := false
	eng.SetBotVerifier(func(_ context.Context, _ netip.Addr) (string, bool) {
		called = true
		return "", false
	})
	act, err := eng.Decide(context.Background(), banVerdicts(netip.MustParseAddr("192.0.2.44")))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Reason != "allowlisted" {
		t.Fatalf("allowlist must win first, got %q", act.Reason)
	}
	if called {
		t.Fatal("bot verifier must not run for allowlisted IPs (allowlist supremacy)")
	}
}
