package enforce

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// unguardedEnforcer is a fake with NO internal allowlist check — it records
// everything it receives. The gate must be the only thing standing between
// it and a guarded target (issue #230 acceptance criterion).
type unguardedEnforcer struct {
	bans   []sdk.Target
	unbans []sdk.Target
	syncs  [][]sdk.Target
}

func (f *unguardedEnforcer) Name() string { return "unguarded" }
func (f *unguardedEnforcer) Ban(_ context.Context, t sdk.Target) error {
	f.bans = append(f.bans, t)
	return nil
}
func (f *unguardedEnforcer) Unban(_ context.Context, t sdk.Target) error {
	f.unbans = append(f.unbans, t)
	return nil
}
func (f *unguardedEnforcer) Sync(_ context.Context, want []sdk.Target) error {
	f.syncs = append(f.syncs, want)
	return nil
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func TestGateBan(t *testing.T) {
	allowlist := []netip.Prefix{
		mustPrefix(t, "192.0.2.0/24"),
		mustPrefix(t, "2001:db8::/32"),
		mustPrefix(t, "198.51.100.7/32"),
	}
	peers := func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.9")} }

	tests := []struct {
		name    string
		target  sdk.Target
		refused bool
	}{
		{"allowlisted ip", sdk.Target{IP: netip.MustParseAddr("192.0.2.10")}, true},
		{"allowlisted ipv6", sdk.Target{IP: netip.MustParseAddr("2001:db8::1")}, true},
		{"ipv4-mapped allowlisted ip", sdk.Target{IP: netip.MustParseAddr("::ffff:192.0.2.10")}, true},
		{"prefix inside allowlist entry", sdk.Target{Prefix: mustPrefix(t, "192.0.2.128/25")}, true},
		{"prefix covering allowlisted host", sdk.Target{Prefix: mustPrefix(t, "198.51.100.0/24")}, true},
		{"active ssh peer", sdk.Target{IP: netip.MustParseAddr("203.0.113.9")}, true},
		{"prefix covering ssh peer", sdk.Target{Prefix: mustPrefix(t, "203.0.113.0/24")}, true},
		{"clean ip", sdk.Target{IP: netip.MustParseAddr("233.252.0.77"), TTL: time.Hour}, false},
		{"clean prefix", sdk.Target{Prefix: mustPrefix(t, "233.252.0.0/24")}, false},
		{"asn target passes through", sdk.Target{ASN: 64496}, false},
		{"country target passes through", sdk.Target{Country: "ZZ"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inner := &unguardedEnforcer{}
			g := NewGate(inner, allowlist, peers)
			err := g.Ban(context.Background(), tc.target)
			if tc.refused {
				if !errors.Is(err, ErrGateRefused) {
					t.Fatalf("Ban = %v, want ErrGateRefused", err)
				}
				if len(inner.bans) != 0 {
					t.Fatalf("inner enforcer received refused target: %+v", inner.bans)
				}
				return
			}
			if err != nil {
				t.Fatalf("Ban = %v, want nil", err)
			}
			if len(inner.bans) != 1 {
				t.Fatalf("inner enforcer got %d bans, want 1", len(inner.bans))
			}
		})
	}
}

func TestGateSyncFiltersGuardedTargets(t *testing.T) {
	allowlist := []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}
	peers := func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.9")} }
	inner := &unguardedEnforcer{}
	g := NewGate(inner, allowlist, peers)

	clean := sdk.Target{IP: netip.MustParseAddr("233.252.0.77")}
	want := []sdk.Target{
		{IP: netip.MustParseAddr("192.0.2.10")}, // allowlisted
		clean,                                   // must survive
		{Prefix: mustPrefix(t, "203.0.113.0/24")},      // covers SSH peer
		{IP: netip.MustParseAddr("::ffff:192.0.2.99")}, // mapped allowlisted
	}
	if err := g.Sync(context.Background(), want); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(inner.syncs) != 1 {
		t.Fatalf("inner got %d Sync calls, want 1", len(inner.syncs))
	}
	got := inner.syncs[0]
	if len(got) != 1 || got[0] != clean {
		t.Fatalf("inner Sync received %+v, want only %+v", got, clean)
	}
}

func TestGateUnbanPassesThrough(t *testing.T) {
	// Unbanning an allowlisted target must not be blocked: removing a ban
	// can only restore access, never lock anyone out.
	inner := &unguardedEnforcer{}
	g := NewGate(inner, []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}, nil)
	if err := g.Unban(context.Background(), sdk.Target{IP: netip.MustParseAddr("192.0.2.10")}); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if len(inner.unbans) != 1 {
		t.Fatalf("inner got %d unbans, want 1", len(inner.unbans))
	}
}

func TestGateNilPeerProbe(t *testing.T) {
	inner := &unguardedEnforcer{}
	g := NewGate(inner, []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}, nil)
	if err := g.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("233.252.0.1")}); err != nil {
		t.Fatalf("Ban with nil probe: %v", err)
	}
	if err := g.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("192.0.2.1")}); !errors.Is(err, ErrGateRefused) {
		t.Fatalf("allowlist must still refuse with nil probe, got %v", err)
	}
}

// TestGateShieldsMultiEnforcer is the issue #230 acceptance scenario: a fake
// enforcer with no internal guard registered behind the MultiEnforcer never
// receives a guarded target via Ban or Sync.
func TestGateShieldsMultiEnforcer(t *testing.T) {
	allowlist := []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}
	peers := func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.9")} }
	a, b := &unguardedEnforcer{}, &unguardedEnforcer{}
	g := NewGate(NewMulti(a, b), allowlist, peers)

	if g.Name() != "unguarded+unguarded" {
		t.Fatalf("Name = %q, want inner name preserved", g.Name())
	}

	guarded := []sdk.Target{
		{IP: netip.MustParseAddr("192.0.2.10")},
		{IP: netip.MustParseAddr("203.0.113.9")},
	}
	for _, tgt := range guarded {
		if err := g.Ban(context.Background(), tgt); !errors.Is(err, ErrGateRefused) {
			t.Fatalf("Ban(%s) = %v, want ErrGateRefused", tgt.IP, err)
		}
	}
	clean := sdk.Target{IP: netip.MustParseAddr("233.252.0.77")}
	if err := g.Sync(context.Background(), append(guarded, clean)); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	for name, f := range map[string]*unguardedEnforcer{"a": a, "b": b} {
		if len(f.bans) != 0 {
			t.Fatalf("enforcer %s received a guarded ban: %+v", name, f.bans)
		}
		if len(f.syncs) != 1 || len(f.syncs[0]) != 1 || f.syncs[0][0] != clean {
			t.Fatalf("enforcer %s Sync state = %+v, want only %+v", name, f.syncs, clean)
		}
	}
}
