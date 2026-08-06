package enforce

// gate.go — centralized allowlist / anti-lockout gate ahead of the enforcer
// fan-out (issue #230).
//
// Individual enforcers keep their own allowlist checks as belt-and-braces,
// but the authoritative guard is here: every Ban/Sync passes through one
// choke point before reaching any enforcer, so a future enforcer that
// forgets its internal check still cannot ban an allowlisted target or an
// operator's live SSH session. This is the enforcement-side backstop of the
// "allowlist always wins" invariant — the decision engine remains the
// primary filter and its semantics are unchanged.
//
// Both target shapes (bare IP and Prefix) and the allowlist itself are
// canonicalized for the overlap checks: IPv4-mapped IPv6 spellings
// (::ffff:a.b.c.d) compare equal to their plain IPv4 forms (issue #365),
// so the backstop holds regardless of which spelling reaches it.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// ErrGateRefused marks a Ban refused by the centralized allowlist /
// anti-lockout gate. Callers can detect it with errors.Is.
var ErrGateRefused = errors.New("refused by allowlist/anti-lockout gate")

// Gate wraps an Enforcer (typically the MultiEnforcer) and refuses any Ban —
// and silently filters any Sync desired-state entry — whose target overlaps
// the allowlist/admin CIDRs or covers an active operator SSH peer. Unban
// always passes through: removing a ban can never lock anyone out.
//
// ASN and Country targets pass through unchecked: they cannot be compared
// against an IP allowlist here; their corroboration rules live in the
// decision engine.
type Gate struct {
	inner     sdk.Enforcer
	allowlist []netip.Prefix
	sshPeers  func() []netip.Addr // kernel-derived operator peers; nil = no peer check
}

// NewGate wraps inner with the centralized guard. allowlist should carry the
// policy allowlist plus admin_cidrs (same slice the enforcers receive); it is
// canonicalized on construction (IPv4-mapped spellings become plain IPv4, see
// normalizeGatePrefix) so a mapped policy entry still protects its plain-v4
// range. sshPeers is typically decision.ProcSSHPeers; nil disables the peer
// check (the allowlist check always runs).
func NewGate(inner sdk.Enforcer, allowlist []netip.Prefix, sshPeers func() []netip.Addr) *Gate {
	norm := make([]netip.Prefix, 0, len(allowlist))
	for _, p := range allowlist {
		norm = append(norm, normalizeGatePrefix(p))
	}
	return &Gate{inner: inner, allowlist: norm, sshPeers: sshPeers}
}

// Name returns the inner enforcer's name; the gate is transparent in logs
// that identify enforcement backends.
func (g *Gate) Name() string { return g.inner.Name() }

// Ban refuses guarded targets with an audited refusal before any enforcer
// sees them; everything else is forwarded to the inner enforcer.
func (g *Gate) Ban(ctx context.Context, t sdk.Target) error {
	if reason, refused := g.refuse(t); refused {
		slog.WarnContext(ctx, "enforce/gate: refusing ban", "target", gateKey(t), "reason", reason)
		return fmt.Errorf("enforce/gate: refusing to ban %s (%s): %w", gateKey(t), reason, ErrGateRefused)
	}
	return g.inner.Ban(ctx, t)
}

// Unban always passes through: removing a ban cannot violate the invariant.
func (g *Gate) Unban(ctx context.Context, t sdk.Target) error {
	return g.inner.Unban(ctx, t)
}

// Sync filters guarded targets out of the desired state with an audited
// refusal each, so a reconcile can never re-introduce them downstream.
func (g *Gate) Sync(ctx context.Context, want []sdk.Target) error {
	filtered := make([]sdk.Target, 0, len(want))
	for _, t := range want {
		if reason, refused := g.refuse(t); refused {
			slog.WarnContext(ctx, "enforce/gate: dropping target from sync", "target", gateKey(t), "reason", reason)
			continue
		}
		filtered = append(filtered, t)
	}
	return g.inner.Sync(ctx, filtered)
}

// Allow forwards the allowlist addition to the inner enforcer's @allowed
// mirror. Allowlist mutations are never gated: widening the allowlist can
// only restore access, never lock anyone out, and this path is itself the
// anti-lockout backstop the gate exists to protect (issue #317). Inners
// without a local allowlist mirror (edge-only setups) make this a no-op.
func (g *Gate) Allow(ctx context.Context, prefix netip.Prefix) error {
	if s, ok := g.inner.(AllowlistSyncer); ok {
		return s.Allow(ctx, prefix)
	}
	return nil
}

// Unallow forwards the allowlist removal to the inner enforcer's @allowed
// mirror; no-op when the inner has none.
func (g *Gate) Unallow(ctx context.Context, prefix netip.Prefix) error {
	if s, ok := g.inner.(AllowlistSyncer); ok {
		return s.Unallow(ctx, prefix)
	}
	return nil
}

// SyncAllowlist forwards the desired allowlist state to the inner enforcer's
// @allowed mirror; no-op when the inner has none.
func (g *Gate) SyncAllowlist(ctx context.Context, want []netip.Prefix) error {
	if s, ok := g.inner.(AllowlistSyncer); ok {
		return s.SyncAllowlist(ctx, want)
	}
	return nil
}

// refuse reports whether the target must be blocked from enforcement and why.
//
// The prefix comparison uses Overlaps, not Contains: banning 192.0.2.0/24
// while 192.0.2.7 is allowlisted would lock that host out even though the
// prefix's base address is not itself allowlisted.
func (g *Gate) refuse(t sdk.Target) (string, bool) {
	p, ok := gatePrefix(t)
	if !ok {
		return "", false
	}
	for _, a := range g.allowlist {
		if a.Overlaps(p) {
			return "allowlisted", true
		}
	}
	if g.sshPeers != nil {
		for _, peer := range g.sshPeers() {
			if p.Contains(peer.Unmap()) {
				return "active SSH peer", true
			}
		}
	}
	return "", false
}

// gatePrefix normalizes an IP or Prefix target into a prefix for overlap
// checks. ASN/Country targets return ok=false (out of the gate's scope).
func gatePrefix(t sdk.Target) (netip.Prefix, bool) {
	if t.IP.IsValid() {
		a := t.IP.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	if t.Prefix.IsValid() {
		return normalizeGatePrefix(t.Prefix), true
	}
	return netip.Prefix{}, false
}

// normalizeGatePrefix canonicalizes an IPv4-mapped IPv6 prefix (::ffff:a.b.c.d
// with bits >= 96) to its plain IPv4 form so mapped and plain spellings
// compare equal in the overlap checks — the enforce-layer mirror of
// decision.NormalizePrefix (issue #365, residue of #314). A mapped prefix
// broader than /96 has no IPv4 equivalent and is left in v6 space (the layers
// above refuse it before enforcement; here it can still overlap v6 entries).
// Non-mapped prefixes are only Masked.
func normalizeGatePrefix(p netip.Prefix) netip.Prefix {
	if !p.Addr().Is4In6() || p.Bits() < 96 {
		return p.Masked()
	}
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked()
}

// gateKey renders a target for refusal logs.
func gateKey(t sdk.Target) string {
	switch {
	case t.IP.IsValid():
		return t.IP.String()
	case t.Prefix.IsValid():
		return t.Prefix.String()
	case t.ASN != 0:
		return fmt.Sprintf("AS%d", t.ASN)
	default:
		return t.Country
	}
}
