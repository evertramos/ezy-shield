package enforce

import (
	"context"
	"errors"
	"net/netip"
	"slices"
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

// allowSyncEnforcer is an unguardedEnforcer that additionally mirrors the
// allowlist (AllowlistSyncer), like the nftables enforcer does. It records
// every call so tests can assert forwarding through Gate/MultiEnforcer.
type allowSyncEnforcer struct {
	unguardedEnforcer
	allows     []netip.Prefix
	unallows   []netip.Prefix
	syncAllows [][]netip.Prefix
	err        error // if set, every allowlist method returns it
}

func (f *allowSyncEnforcer) Allow(_ context.Context, p netip.Prefix) error {
	f.allows = append(f.allows, p)
	return f.err
}
func (f *allowSyncEnforcer) Unallow(_ context.Context, p netip.Prefix) error {
	f.unallows = append(f.unallows, p)
	return f.err
}
func (f *allowSyncEnforcer) SyncAllowlist(_ context.Context, want []netip.Prefix) error {
	c := make([]netip.Prefix, len(want))
	copy(c, want)
	f.syncAllows = append(f.syncAllows, c)
	return f.err
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

// TestGateForwardsAllowlistSyncer covers issue #317: the Gate must keep the
// inner enforcer's allowlist mirror reachable — hiding it leaves the kernel
// @allowed sets empty and kills the ADR-0007 anti-lockout backstop. The
// production shape Gate(Multi(nftables-like, edge-like)) is exercised so the
// full wrapper chain forwards, and the edge enforcer (no AllowlistSyncer)
// is skipped without error.
func TestGateForwardsAllowlistSyncer(t *testing.T) {
	local := &allowSyncEnforcer{}
	edge := &unguardedEnforcer{} // no allowlist mirror, like Cloudflare
	g := NewGate(NewMulti(local, edge), []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}, nil)

	pfx := mustPrefix(t, "203.0.113.7/32")
	want := []netip.Prefix{pfx, mustPrefix(t, "10.0.0.0/8")}

	if err := g.Allow(context.Background(), pfx); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if err := g.Unallow(context.Background(), pfx); err != nil {
		t.Fatalf("Unallow: %v", err)
	}
	if err := g.SyncAllowlist(context.Background(), want); err != nil {
		t.Fatalf("SyncAllowlist: %v", err)
	}

	if len(local.allows) != 1 || local.allows[0] != pfx {
		t.Errorf("inner Allow calls = %v, want [%v]", local.allows, pfx)
	}
	if len(local.unallows) != 1 || local.unallows[0] != pfx {
		t.Errorf("inner Unallow calls = %v, want [%v]", local.unallows, pfx)
	}
	if len(local.syncAllows) != 1 || !slices.Equal(local.syncAllows[0], want) {
		t.Errorf("inner SyncAllowlist calls = %v, want one call with %v", local.syncAllows, want)
	}
}

// TestGateAllowlistNoOpWithoutInnerSyncer: an edge-only chain (no local
// firewall) has nothing to mirror into; the forwarded methods must be silent
// no-ops, preserving pre-#230 behaviour where the daemon's type assertion
// simply failed and skipped the sync.
func TestGateAllowlistNoOpWithoutInnerSyncer(t *testing.T) {
	g := NewGate(&unguardedEnforcer{}, nil, nil)
	pfx := mustPrefix(t, "203.0.113.7/32")
	if err := g.Allow(context.Background(), pfx); err != nil {
		t.Fatalf("Allow on edge-only inner: %v", err)
	}
	if err := g.Unallow(context.Background(), pfx); err != nil {
		t.Fatalf("Unallow on edge-only inner: %v", err)
	}
	if err := g.SyncAllowlist(context.Background(), []netip.Prefix{pfx}); err != nil {
		t.Fatalf("SyncAllowlist on edge-only inner: %v", err)
	}
}

// TestMultiAllowlistFanOutJoinsErrors: a failing local mirror must surface in
// the joined error (so the daemon logs it) while the healthy one still gets
// the call — matching Ban/Unban/Sync fan-out semantics.
func TestMultiAllowlistFanOutJoinsErrors(t *testing.T) {
	bad := &allowSyncEnforcer{err: errors.New("nft exploded")}
	good := &allowSyncEnforcer{}
	m := NewMulti(bad, good, &unguardedEnforcer{})

	pfx := mustPrefix(t, "203.0.113.7/32")
	if err := m.Allow(context.Background(), pfx); err == nil {
		t.Fatal("Allow: want joined error from failing enforcer, got nil")
	}
	if err := m.Unallow(context.Background(), pfx); err == nil {
		t.Fatal("Unallow: want joined error from failing enforcer, got nil")
	}
	if err := m.SyncAllowlist(context.Background(), []netip.Prefix{pfx}); err == nil {
		t.Fatal("SyncAllowlist: want joined error from failing enforcer, got nil")
	}
	for name, f := range map[string]*allowSyncEnforcer{"bad": bad, "good": good} {
		if len(f.allows) != 1 || len(f.unallows) != 1 || len(f.syncAllows) != 1 {
			t.Errorf("enforcer %s calls = allow:%d unallow:%d sync:%d, want 1/1/1 (fan-out must reach every syncer)",
				name, len(f.allows), len(f.unallows), len(f.syncAllows))
		}
	}
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

// ── issue #365: IPv4-mapped canonicalization at the enforce layer ────────────

// TestGateMappedPrefixTargets reproduces issue #365 (residue of #314/#364):
// Prefix-shaped targets in the IPv4-mapped IPv6 spelling did not Overlap
// plain-v4 allowlist entries, so the Gate's belt-and-braces refusal missed
// them. The Gate's job is to hold even when the layers above are bugged, so
// it must canonicalize both target shapes, not just bare IPs.
func TestGateMappedPrefixTargets(t *testing.T) {
	allowlist := []netip.Prefix{
		mustPrefix(t, "192.0.2.0/24"),
		mustPrefix(t, "198.51.100.7/32"),
	}
	peers := func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.9")} }

	tests := []struct {
		name    string
		target  sdk.Target
		refused bool
	}{
		{"mapped prefix inside plain allowlist entry", sdk.Target{Prefix: mustPrefix(t, "::ffff:192.0.2.0/120")}, true},
		{"mapped host-prefix of allowlisted host", sdk.Target{Prefix: mustPrefix(t, "::ffff:198.51.100.7/128")}, true},
		{"mapped prefix covering ssh peer", sdk.Target{Prefix: mustPrefix(t, "::ffff:203.0.113.0/120")}, true},
		{"clean mapped prefix", sdk.Target{Prefix: mustPrefix(t, "::ffff:233.252.0.0/120")}, false},
		{"broad mapped prefix (<96, no v4 equivalent) stays v6", sdk.Target{Prefix: mustPrefix(t, "::ffff:0:0/95")}, false},
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
		})
	}
}

// TestGateMappedAllowlistEntries: a policy allowlist entry written in the
// mapped spelling must still protect the plain-v4 target (issue #365: the
// slice handed to NewGate is canonicalized on construction).
func TestGateMappedAllowlistEntries(t *testing.T) {
	allowlist := []netip.Prefix{mustPrefix(t, "::ffff:192.0.2.0/120")}
	inner := &unguardedEnforcer{}
	g := NewGate(inner, allowlist, nil)

	for _, target := range []sdk.Target{
		{IP: netip.MustParseAddr("192.0.2.10")},
		{Prefix: mustPrefix(t, "192.0.2.128/25")},
	} {
		if err := g.Ban(context.Background(), target); !errors.Is(err, ErrGateRefused) {
			t.Errorf("Ban(%+v) = %v, want ErrGateRefused (mapped allowlist entry must protect plain target)", target, err)
		}
	}
	if len(inner.bans) != 0 {
		t.Fatalf("inner enforcer received refused targets: %+v", inner.bans)
	}
}

// TestGateSyncFiltersMappedPrefix: the Sync filter path uses the same
// canonicalization as Ban.
func TestGateSyncFiltersMappedPrefix(t *testing.T) {
	allowlist := []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}
	inner := &unguardedEnforcer{}
	g := NewGate(inner, allowlist, nil)

	clean := sdk.Target{IP: netip.MustParseAddr("233.252.0.77")}
	want := []sdk.Target{
		{Prefix: mustPrefix(t, "::ffff:192.0.2.0/121")}, // mapped, inside allowlist
		clean,
	}
	if err := g.Sync(context.Background(), want); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	got := inner.syncs[0]
	if len(got) != 1 || got[0] != clean {
		t.Fatalf("inner Sync received %+v, want only %+v", got, clean)
	}
}
