package decision

// manualban.go — guards for operator-issued bans (issue #211).
//
// Automatic decisions pass through Decide, where the allowlist check, the
// SSH-peer anti-lockout re-derivation, and max_bans_per_minute gate every
// rule write. The manual path (CLI → unix socket) previously relied only on
// the enforcer-layer allowlist, so a fat-fingered `ezyshield ban` of your
// own session bypassed every engine guard. AuthorizeManualBan closes that:
// the daemon MUST call it before acting on any manual ban.
//
// There is deliberately NO override for the hard guards: allowlist and
// anti-lockout are hard rules (AGENTS.md §1), and the rate limit is the
// runaway safety valve — the policy knob for legitimate bulk operator work
// is max_bans_per_minute, not a bypass flag. The one exception is the CDN
// shared-range guard (issue #178), overridable with --force because it rests
// on a shipped data snapshot rather than operator intent.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
)

// ErrManualBanAllowlisted is returned when a manual ban target overlaps the
// policy allowlist or admin_cidrs. Never overridable: allowlist always wins.
var ErrManualBanAllowlisted = errors.New("target overlaps the allowlist/admin_cidrs")

// ErrManualBanSSHPeer is returned when a manual ban target covers an active
// SSH session (the daemon's own derivation or a peer forwarded by the CLI).
// Never overridable: this is the anti-lockout invariant.
var ErrManualBanSSHPeer = errors.New("target covers an active SSH session")

// ErrManualBanCDNRange is returned when a manual ban target overlaps a known
// shared CDN edge range (issue #178) — blocking a shared edge IP blocks
// legitimate traffic for everyone behind that CDN. Overridable with --force:
// unlike the allowlist (operator intent) this is a shipped data snapshot
// that can go stale, so a deliberate operator override must stay possible.
var ErrManualBanCDNRange = errors.New("target overlaps a known shared CDN edge range (use --force to override)")

// ErrManualBanCDNUnverified is returned when the CDN range table is
// unavailable and the ban therefore cannot be verified against shared edge
// ranges (issue #178). Overridable with --force.
var ErrManualBanCDNUnverified = errors.New("CDN range data unavailable — target cannot be verified against shared edge ranges (use --force to ban anyway)")

// AuthorizeManualBan applies the same safety guards to an operator-issued
// ban that Decide applies to automatic ones. target is the requested ban
// prefix (a single IP arrives as a host prefix). peers carries additional
// operator-session IPs to protect — in practice the CLI's own SSH client IP
// forwarded over the socket, since the daemon's environment has no
// SSH_CLIENT under systemd (issue #175 will add /proc-based derivation on
// top; both paths funnel through here).
//
// Guard order mirrors Decide: allowlist first (always wins), anti-lockout
// second, and the rate limit last — the shared fixed-window budget is only
// consumed by bans that the safety guards actually admit. The rate limit is
// counted in dry-run too, mirroring ADR-0009 §5 (dry-run reproduces exactly
// the decisions production would take).
//
// The returned errors are typed (ErrManualBanAllowlisted, ErrManualBanSSHPeer,
// ErrRateLimited) and carry the specific entry that fired, so refusals can be
// audited and reported to the operator by name.
// force bypasses ONLY the CDN-range guards (match and data-unavailable) —
// never the allowlist, the SSH anti-lockout, or the rate limit.
func (e *Engine) AuthorizeManualBan(ctx context.Context, target netip.Prefix, force bool, peers ...netip.Addr) error {
	// Normalize the IPv4-mapped IPv6 spelling operators copy from dual-stack
	// logs ("ezyshield ban ::ffff:a.b.c.d") — netip treats it as distinct
	// from the plain form, which would bypass every Overlaps/Contains guard
	// below (issue #314). A mapped super-prefix broader than /96 has no IPv4
	// equivalent, so no guard below could refuse it — reject it outright
	// rather than authorize a target the allowlist can't see (PR #364
	// review). The refusal is audited like any other via the socket handler.
	var err error
	if target, err = NormalizePrefix(target); err != nil {
		return fmt.Errorf("refusing manual ban: %w", err)
	}

	// ── Safety invariant §1: allowlist checked FIRST, always wins ─────────
	// Overlap in either direction refuses: banning a prefix that contains an
	// allowlisted range would lock the allowlisted hosts out just as surely
	// as banning them directly.
	for _, p := range e.allow {
		if p.Overlaps(target) {
			return fmt.Errorf("%w: %s overlaps %s", ErrManualBanAllowlisted, target, p)
		}
	}

	// ── Safety invariant §1: anti-lockout — every known operator session ──
	// Daemon-side derivation re-checked on every call: SSH_CLIENT plus the
	// kernel-derived peers that exist under systemd (issue #175), then every
	// CLI-forwarded peer.
	for _, peer := range e.activeSSHPeers() {
		if target.Contains(peer) {
			return fmt.Errorf("%w: %s contains SSH peer %s", ErrManualBanSSHPeer, target, peer)
		}
	}
	for _, peer := range peers {
		// CLI-forwarded peers come from the client's SSH_CLIENT, which a
		// dual-stack sshd reports in mapped form (issue #314).
		peer = peer.Unmap()
		if peer.IsValid() && target.Contains(peer) {
			return fmt.Errorf("%w: %s contains your session's IP %s", ErrManualBanSSHPeer, target, peer)
		}
	}

	// ── Safety invariant §1: shared CDN edge ranges (issue #178) ──────────
	// Force-overridable (see the error docs); a forced override is loud.
	if e.cdnRanges != nil && !force {
		ranges, err := e.cdnRanges()
		if err != nil {
			e.warnCDNRangesUnavailable(ctx, err)
			return fmt.Errorf("refusing manual ban of %s: %w", target, ErrManualBanCDNUnverified)
		}
		for _, p := range ranges {
			if p.Overlaps(target) {
				return fmt.Errorf("%w: %s overlaps %s", ErrManualBanCDNRange, target, p)
			}
		}
	} else if e.cdnRanges != nil && force {
		slog.WarnContext(ctx, "decision: manual ban with --force — CDN shared-range guard bypassed",
			"target", target.String())
	}

	// ── Safety invariant §1: rate limit — shared window with Decide ───────
	// A manual ban is still a ban: bulk socket-driven bans must not bypass
	// the runaway valve that bounds automatic ones.
	return e.checkRateLimit()
}
