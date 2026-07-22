package decision_test

// Integration tests for issue #175: the anti-lockout guards consume
// kernel-derived SSH peers (the path that exists under systemd, where
// SSH_CLIENT does not), for BOTH automatic decisions and manual bans.
// The probe is injected; the parser itself is covered fixture-by-fixture
// in sshpeers_test.go.

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestAntiLockout_ProcDerivedPeer_AutomaticDecision(t *testing.T) {
	t.Parallel()
	peer := netip.MustParseAddr("203.0.113.61")
	st := newMock(nil)
	eng := mustEngine(t, armedPolicy(), st)
	eng.SetSSHPeerProbe(func() []netip.Addr { return []netip.Addr{peer} })

	act, err := eng.Decide(context.Background(), []sdk.Verdict{mkVerdict(peer, 100, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "record" || act.Reason != "anti-lockout: active SSH peer" {
		t.Errorf("Op=%q Reason=%q — kernel-derived peer not protected", act.Op, act.Reason)
	}
	if len(st.banned) != 0 {
		t.Error("RecordStrike called for a kernel-derived SSH peer")
	}

	// A different IP still gets banned — the probe protects the peer only.
	other := netip.MustParseAddr("203.0.113.62")
	act, err = eng.Decide(context.Background(), []sdk.Verdict{mkVerdict(other, 100, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide other: %v", err)
	}
	if act.Op != "ban" {
		t.Errorf("non-peer Op = %q, want ban", act.Op)
	}
}

func TestAntiLockout_ProcDerivedPeer_ManualBan(t *testing.T) {
	t.Parallel()
	peer := netip.MustParseAddr("203.0.113.61")
	eng := mustEngine(t, armedPolicy(), newMock(nil))
	eng.SetSSHPeerProbe(func() []netip.Addr { return []netip.Addr{peer} })

	err := eng.AuthorizeManualBan(context.Background(), hostPrefix("203.0.113.61"))
	if !errors.Is(err, decision.ErrManualBanSSHPeer) {
		t.Errorf("manual ban of kernel-derived peer: err = %v, want ErrManualBanSSHPeer", err)
	}
	// A CIDR covering the peer is refused too.
	err = eng.AuthorizeManualBan(context.Background(), netip.MustParsePrefix("203.0.113.0/24"))
	if !errors.Is(err, decision.ErrManualBanSSHPeer) {
		t.Errorf("manual CIDR ban covering kernel-derived peer: err = %v, want ErrManualBanSSHPeer", err)
	}
}
