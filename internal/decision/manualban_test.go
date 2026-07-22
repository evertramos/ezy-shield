package decision_test

// Tests for AuthorizeManualBan (issue #211): manual bans pass the exact
// guard set automatic decisions get — allowlist wins (overlap in either
// direction), SSH-peer anti-lockout (daemon env + forwarded peers), and the
// shared ban rate limit. None of the guards is overridable.

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/evertramos/ezy-shield/internal/decision"
)

func hostPrefix(ip string) netip.Prefix {
	a := netip.MustParseAddr(ip)
	return netip.PrefixFrom(a, a.BitLen())
}

func TestAuthorizeManualBan_AllowlistWins(t *testing.T) {
	pol := armedPolicy()
	pol.Allowlist = []string{"203.0.113.10", "198.51.100.0/24"}
	pol.AdminCIDRs = []string{"192.0.2.0/28"}
	eng := mustEngine(t, pol, newMock(nil))

	cases := []struct {
		name   string
		target netip.Prefix
	}{
		{"exact allowlisted IP", hostPrefix("203.0.113.10")},
		{"IP inside allowlisted CIDR", hostPrefix("198.51.100.77")},
		{"CIDR containing an allowlisted IP", netip.MustParsePrefix("203.0.113.0/24")},
		{"CIDR containing an allowlisted CIDR", netip.MustParsePrefix("198.51.0.0/16")},
		{"IP inside admin_cidrs", hostPrefix("192.0.2.5")},
		{"CIDR overlapping admin_cidrs", netip.MustParsePrefix("192.0.2.0/24")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := eng.AuthorizeManualBan(context.Background(), tc.target)
			if !errors.Is(err, decision.ErrManualBanAllowlisted) {
				t.Errorf("err = %v, want ErrManualBanAllowlisted", err)
			}
		})
	}
}

func TestAuthorizeManualBan_DaemonSSHPeerRefused(t *testing.T) {
	// Engine built with no SSH_CLIENT; the peer appears afterwards — the
	// guard must re-derive it per call (sessions started after the daemon).
	eng := mustEngine(t, armedPolicy(), newMock(nil))
	t.Setenv("SSH_CLIENT", "203.0.113.50 51000 22")

	err := eng.AuthorizeManualBan(context.Background(), hostPrefix("203.0.113.50"))
	if !errors.Is(err, decision.ErrManualBanSSHPeer) {
		t.Errorf("banning the env-derived SSH peer: err = %v, want ErrManualBanSSHPeer", err)
	}
	// A CIDR covering the peer is just as much a lockout.
	err = eng.AuthorizeManualBan(context.Background(), netip.MustParsePrefix("203.0.113.0/24"))
	if !errors.Is(err, decision.ErrManualBanSSHPeer) {
		t.Errorf("banning a CIDR covering the SSH peer: err = %v, want ErrManualBanSSHPeer", err)
	}
}

func TestAuthorizeManualBan_ForwardedPeerRefused(t *testing.T) {
	t.Parallel()
	eng := mustEngine(t, armedPolicy(), newMock(nil))
	operator := netip.MustParseAddr("198.51.100.9")

	err := eng.AuthorizeManualBan(context.Background(), hostPrefix("198.51.100.9"), operator)
	if !errors.Is(err, decision.ErrManualBanSSHPeer) {
		t.Errorf("banning the CLI-forwarded peer: err = %v, want ErrManualBanSSHPeer", err)
	}
	// Invalid (zero) forwarded peers are ignored, not matched.
	if err := eng.AuthorizeManualBan(context.Background(), hostPrefix("192.0.2.7"), netip.Addr{}); err != nil {
		t.Errorf("zero-value peer must be ignored: %v", err)
	}
}

func TestAuthorizeManualBan_RateLimitSharedAndOrdered(t *testing.T) {
	t.Parallel()
	pol := armedPolicy()
	pol.MaxBansPerMinute = 2
	pol.Allowlist = []string{"203.0.113.10"}
	eng := mustEngine(t, pol, newMock(nil))
	ctx := context.Background()

	// Refused-by-allowlist attempts must NOT consume the rate budget: the
	// guard order is allowlist → anti-lockout → rate limit.
	for i := 0; i < 5; i++ {
		if err := eng.AuthorizeManualBan(ctx, hostPrefix("203.0.113.10")); !errors.Is(err, decision.ErrManualBanAllowlisted) {
			t.Fatalf("attempt %d: err = %v, want allowlist refusal", i, err)
		}
	}

	// Two admitted bans fit the cap; the third trips it.
	if err := eng.AuthorizeManualBan(ctx, hostPrefix("192.0.2.1")); err != nil {
		t.Fatalf("first admitted ban: %v", err)
	}
	if err := eng.AuthorizeManualBan(ctx, hostPrefix("192.0.2.2")); err != nil {
		t.Fatalf("second admitted ban: %v", err)
	}
	if err := eng.AuthorizeManualBan(ctx, hostPrefix("192.0.2.3")); !errors.Is(err, decision.ErrRateLimited) {
		t.Errorf("third ban: err = %v, want ErrRateLimited (manual bans share the cap)", err)
	}
}

func TestAuthorizeManualBan_ValidBanPasses(t *testing.T) {
	t.Parallel()
	pol := armedPolicy()
	pol.Allowlist = []string{"198.51.100.0/24"}
	eng := mustEngine(t, pol, newMock(nil))

	if err := eng.AuthorizeManualBan(context.Background(), hostPrefix("192.0.2.200")); err != nil {
		t.Errorf("legitimate manual ban refused: %v", err)
	}
	if err := eng.AuthorizeManualBan(context.Background(), netip.MustParsePrefix("192.0.2.0/29")); err != nil {
		t.Errorf("legitimate CIDR manual ban refused: %v", err)
	}
}
