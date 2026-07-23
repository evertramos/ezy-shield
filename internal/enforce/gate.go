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
// policy allowlist plus admin_cidrs (same slice the enforcers receive).
// sshPeers is typically decision.ProcSSHPeers; nil disables the peer check
// (the allowlist check always runs).
func NewGate(inner sdk.Enforcer, allowlist []netip.Prefix, sshPeers func() []netip.Addr) *Gate {
	return &Gate{inner: inner, allowlist: allowlist, sshPeers: sshPeers}
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
		return t.Prefix.Masked(), true
	}
	return netip.Prefix{}, false
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
