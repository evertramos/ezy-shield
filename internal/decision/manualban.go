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
// There is deliberately NO override for any of these guards: allowlist and
// anti-lockout are hard rules (AGENTS.md §1), and the rate limit is the
// runaway safety valve — the policy knob for legitimate bulk operator work
// is max_bans_per_minute, not a bypass flag.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// ErrManualBanAllowlisted is returned when a manual ban target overlaps the
// policy allowlist or admin_cidrs. Never overridable: allowlist always wins.
var ErrManualBanAllowlisted = errors.New("target overlaps the allowlist/admin_cidrs")

// ErrManualBanSSHPeer is returned when a manual ban target covers an active
// SSH session (the daemon's own derivation or a peer forwarded by the CLI).
// Never overridable: this is the anti-lockout invariant.
var ErrManualBanSSHPeer = errors.New("target covers an active SSH session")

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
func (e *Engine) AuthorizeManualBan(_ context.Context, target netip.Prefix, peers ...netip.Addr) error {
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
		if peer.IsValid() && target.Contains(peer) {
			return fmt.Errorf("%w: %s contains your session's IP %s", ErrManualBanSSHPeer, target, peer)
		}
	}

	// ── Safety invariant §1: rate limit — shared window with Decide ───────
	// A manual ban is still a ban: bulk socket-driven bans must not bypass
	// the runaway valve that bounds automatic ones.
	return e.checkRateLimit()
}
