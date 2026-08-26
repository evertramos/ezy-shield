// SPDX-License-Identifier: AGPL-3.0-only

package decision_test

// Tests for the shared-CDN-range ban guard (issue #178): a shared CDN edge
// IP must never be banned, and "range data unavailable" is a distinct,
// detectable state — never a silent no-match.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// cdnFixtureRange stands in for a shared CDN edge range (RFC 5737 TEST-NET-2).
const cdnFixtureRange = "198.51.100.0/25"

func cdnGuardEngine(t *testing.T, st decision.Store, ranges []netip.Prefix, rangesErr error) *decision.Engine {
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
	eng.SetCDNRangeSource(func() ([]netip.Prefix, error) { return ranges, rangesErr })
	return eng
}

func banVerdicts(ip netip.Addr) []sdk.Verdict {
	return []sdk.Verdict{{IP: ip, Score: 95, Category: "bruteforce", Reason: "test", Source: "rules"}}
}

// TestDecide_RefusesSharedCDNEdgeIP: with ranges loaded, a ban-worthy score
// on an IP inside a known CDN range is refused (Op record, stable reason).
func TestDecide_RefusesSharedCDNEdgeIP(t *testing.T) {
	t.Parallel()
	st := newMock(nil)
	eng := cdnGuardEngine(t, st, []netip.Prefix{netip.MustParsePrefix(cdnFixtureRange)}, nil)

	ip := netip.MustParseAddr("198.51.100.7") // inside the fixture range
	act, err := eng.Decide(context.Background(), banVerdicts(ip))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "record" || act.Reason != decision.ReasonAntiLockoutCDNRange {
		t.Fatalf("shared CDN edge IP must be refused, got Op=%q Reason=%q", act.Op, act.Reason)
	}
	if len(st.banned) != 0 {
		t.Fatalf("RecordStrike must never run for a CDN edge IP (%d calls)", len(st.banned))
	}
}

// TestDecide_UnavailableRangesMarkBanUnverified: with the range table
// unavailable, the ban PROCEEDS (refusing every ban would disable
// protection) but the audit reason carries the unverified marker — the
// guardrail the issue's empty-data test demands.
func TestDecide_UnavailableRangesMarkBanUnverified(t *testing.T) {
	t.Parallel()
	st := newMock(nil)
	eng := cdnGuardEngine(t, st, nil, fmt.Errorf("table failed to load"))

	// The known-CDN fixture IP: with EMPTY/unavailable ranges the match
	// cannot fire — the engaged guardrail is the audit marker + WARN.
	ip := netip.MustParseAddr("198.51.100.7")
	act, err := eng.Decide(context.Background(), banVerdicts(ip))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "dry_ban" {
		t.Fatalf("ban must proceed when range data is unavailable, got %q", act.Op)
	}
	if !strings.Contains(act.Reason, decision.ReasonMarkCDNUnverified) {
		t.Fatalf("audit reason must record the unverified state, got %q", act.Reason)
	}
}

// TestDecide_LoadedRangesLeaveOutsideIPsUnchanged: with ranges loaded, an IP
// outside them is sentenced exactly as before — no marker, no refusal.
func TestDecide_LoadedRangesLeaveOutsideIPsUnchanged(t *testing.T) {
	t.Parallel()
	st := newMock(nil)
	eng := cdnGuardEngine(t, st, []netip.Prefix{netip.MustParsePrefix(cdnFixtureRange)}, nil)

	ip := netip.MustParseAddr("203.0.113.9") // outside every fixture range
	act, err := eng.Decide(context.Background(), banVerdicts(ip))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "dry_ban" {
		t.Fatalf("normal sentencing expected, got %q", act.Op)
	}
	if strings.Contains(act.Reason, decision.ReasonMarkCDNUnverified) {
		t.Fatalf("no unverified marker may appear when ranges are loaded: %q", act.Reason)
	}
}

// TestAuthorizeManualBan_CDNGuards: manual bans refuse CDN-range overlaps and
// unavailable data — both overridable with force, and force never weakens the
// allowlist guard.
func TestAuthorizeManualBan_CDNGuards(t *testing.T) {
	t.Parallel()
	target := netip.MustParsePrefix("198.51.100.7/32")

	t.Run("range overlap refused without force", func(t *testing.T) {
		t.Parallel()
		eng := cdnGuardEngine(t, newMock(nil), []netip.Prefix{netip.MustParsePrefix(cdnFixtureRange)}, nil)
		err := eng.AuthorizeManualBan(context.Background(), target, false)
		if !errors.Is(err, decision.ErrManualBanCDNRange) {
			t.Fatalf("want ErrManualBanCDNRange, got %v", err)
		}
	})

	t.Run("range overlap allowed with force", func(t *testing.T) {
		t.Parallel()
		eng := cdnGuardEngine(t, newMock(nil), []netip.Prefix{netip.MustParsePrefix(cdnFixtureRange)}, nil)
		if err := eng.AuthorizeManualBan(context.Background(), target, true); err != nil {
			t.Fatalf("force must bypass the CDN-range guard, got %v", err)
		}
	})

	t.Run("unavailable data refused without force", func(t *testing.T) {
		t.Parallel()
		eng := cdnGuardEngine(t, newMock(nil), nil, fmt.Errorf("no data"))
		err := eng.AuthorizeManualBan(context.Background(), netip.MustParsePrefix("203.0.113.9/32"), false)
		if !errors.Is(err, decision.ErrManualBanCDNUnverified) {
			t.Fatalf("want ErrManualBanCDNUnverified, got %v", err)
		}
	})

	t.Run("unavailable data allowed with force", func(t *testing.T) {
		t.Parallel()
		eng := cdnGuardEngine(t, newMock(nil), nil, fmt.Errorf("no data"))
		if err := eng.AuthorizeManualBan(context.Background(), netip.MustParsePrefix("203.0.113.9/32"), true); err != nil {
			t.Fatalf("force must bypass the unavailable-data refusal, got %v", err)
		}
	})
}
