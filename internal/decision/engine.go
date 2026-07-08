// Package decision is the safety-critical policy engine that converts Verdicts
// into enforceable Actions. It enforces allowlists, anti-lockout checks, strike
// escalation, global rate limiting, and dry-run mode.
//
// Safety invariants (AGENTS.md Hard Rule §1):
//   - Allowlist always wins: checked before any other logic, unbypassable.
//   - Anti-lockout: active SSH peer (SSH_CLIENT) is re-derived before every ban.
//   - Dry-run default: Op="dry_ban", no store writes, until policy.Armed=true.
//   - Max-bans-per-minute cap: breach returns ErrRateLimited, never silently drops.
package decision

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// ErrRateLimited is returned by Decide when the global ban-rate cap is exceeded.
// Callers should pause enforcement and send a critical alert.
var ErrRateLimited = errors.New("decision: global ban rate limit exceeded")

// Store is the persistence interface required by Engine.
// The concrete *store.DB satisfies this interface.
type Store interface {
	// HasActiveBan returns true when ip has an unexpired row in bans_active,
	// false when it does not. The engine calls this before GetStrikeCount to
	// suppress redundant strike/enforcer writes for already-banned IPs.
	HasActiveBan(ctx context.Context, ip netip.Addr) (bool, error)
	// BumpLastSeen updates offenders.last_seen for ip without recording a strike.
	// It is the only store write on the suppression path.
	BumpLastSeen(ctx context.Context, ip netip.Addr) error
	// GetStrikeCount returns the cumulative strike count for ip (0 if never seen).
	GetStrikeCount(ctx context.Context, ip netip.Addr) (int, error)
	// RecordStrike persists a ban strike and updates bans_active + audit_log.
	RecordStrike(ctx context.Context, a sdk.Action) error
	// Audit appends a record to the append-only audit_log without recording a strike.
	Audit(ctx context.Context, a sdk.Action) error
}

// Engine converts Verdicts into Actions according to policy.
// It is safe for concurrent use.
type Engine struct {
	policy *config.Policy
	store  Store
	allow  []netip.Prefix // static allowlist built at construction time

	mu          sync.Mutex
	bansInWin   int
	windowStart time.Time
}

// New creates an Engine from policy and a store.
//
// The static allowlist is built from policy.Allowlist, policy.AdminCIDRs, and
// the SSH peer present in the SSH_CLIENT environment variable at call time (anti-lockout
// at startup). The SSH peer is also re-checked dynamically inside Decide before
// every ban to guard against sessions that start after the daemon.
func New(policy *config.Policy, st Store) (*Engine, error) {
	allow, err := buildAllowlist(policy)
	if err != nil {
		return nil, err
	}
	return &Engine{
		policy:      policy,
		store:       st,
		allow:       allow,
		windowStart: time.Now(),
	}, nil
}

// Decide evaluates verdicts for a single IP and returns the Action to take.
// All verdicts must share the same IP; the one with the highest score drives the
// decision while all are included in the returned Action.Verdicts.
//
// Score bands (from policy):
//   - score < observe_threshold  → Op="record"
//   - observe_threshold ≤ score < ban_threshold → Op="notify_only"
//   - score ≥ ban_threshold → Op="ban" (or "dry_ban" when not armed)
func (e *Engine) Decide(ctx context.Context, verdicts []sdk.Verdict) (sdk.Action, error) {
	if len(verdicts) == 0 {
		return sdk.Action{}, fmt.Errorf("decision: Decide called with empty verdicts")
	}

	// Pick the highest-scoring verdict; all verdicts are forwarded in the Action.
	best := verdicts[0]
	for _, v := range verdicts[1:] {
		if v.Score > best.Score {
			best = v
		}
	}
	ip := best.IP

	// ── Safety invariant §1: allowlist checked FIRST, always wins ─────────────
	if e.isAllowlisted(ip) {
		slog.InfoContext(ctx, "decision: allowlisted — no action", "ip", ip)
		act := sdk.Action{IP: ip, Op: "record", Reason: "allowlisted", Verdicts: verdicts}
		if err := e.store.Audit(ctx, act); err != nil {
			slog.ErrorContext(ctx, "decision: audit allowlisted", "ip", ip, "err", err)
		}
		return act, nil
	}

	// ── Safety invariant §1: anti-lockout — re-derive SSH peer before every ban ─
	if peer := sshClientIP(); peer.IsValid() && peer == ip {
		slog.WarnContext(ctx, "decision: anti-lockout — refusing to ban active SSH peer", "ip", ip)
		act := sdk.Action{IP: ip, Op: "record", Reason: "anti-lockout: active SSH peer", Verdicts: verdicts}
		if err := e.store.Audit(ctx, act); err != nil {
			slog.ErrorContext(ctx, "decision: audit anti-lockout", "ip", ip, "err", err)
		}
		return act, nil
	}

	score := best.Score

	// Below observe threshold → record only (no notification).
	if score < e.policy.ObserveThreshold {
		act := sdk.Action{IP: ip, Op: "record", Reason: best.Reason, Verdicts: verdicts}
		if err := e.store.Audit(ctx, act); err != nil {
			slog.ErrorContext(ctx, "decision: audit record-only", "ip", ip, "err", err)
		}
		return act, nil
	}

	// Observe band → notify only, no strike.
	if score < e.policy.BanThreshold {
		act := sdk.Action{IP: ip, Op: "notify_only", Reason: best.Reason, Verdicts: verdicts}
		if err := e.store.Audit(ctx, act); err != nil {
			slog.ErrorContext(ctx, "decision: audit notify-only", "ip", ip, "err", err)
		}
		return act, nil
	}

	// ── Active-ban guard (issue #28) ─────────────────────────────────────────
	// If the IP already has an active ban (temp or permanent), suppress the
	// strike/audit/enforcer writes. Only offenders.last_seen is bumped so the
	// IP still appears as "active" in observability. bans_active remains the
	// enforcer source of truth; the Sync loop handles expiry races.
	//
	// Dry-run is handled further below — we still skip the store check in
	// dry-run mode because RecordStrike is also skipped there. The guard runs
	// only when armed=true to preserve the current dry-run semantics unchanged.
	if e.policy.Armed {
		banned, err := e.store.HasActiveBan(ctx, ip)
		if err != nil {
			// Non-fatal: log and fall through to the normal strike path rather
			// than silently suppressing a verdict on a DB error.
			slog.ErrorContext(ctx, "decision: HasActiveBan failed — falling through to strike path",
				"ip", ip, "err", err)
		} else if banned {
			slog.InfoContext(ctx, "decision: already_banned — suppressing strike/enforcer",
				"ip", ip)
			act := sdk.Action{IP: ip, Op: "already_banned", Reason: "active ban in bans_active", Verdicts: verdicts}
			if err := e.store.BumpLastSeen(ctx, ip); err != nil {
				slog.ErrorContext(ctx, "decision: BumpLastSeen failed", "ip", ip, "err", err)
			}
			return act, nil
		}
	}

	// score ≥ ban_threshold → compute strike escalation.
	existing, err := e.store.GetStrikeCount(ctx, ip)
	if err != nil {
		return sdk.Action{}, fmt.Errorf("decision: GetStrikeCount: %w", err)
	}

	nextStrike := existing + 1
	idx := nextStrike - 1
	if idx >= len(e.policy.Strikes) {
		idx = len(e.policy.Strikes) - 1
	}
	ttl := e.policy.Strikes[idx].TTL.AsDuration()

	op := "ban"
	if !e.policy.Armed {
		op = "dry_ban"
	}

	act := sdk.Action{
		IP:       ip,
		Op:       op,
		TTL:      ttl,
		Strike:   nextStrike,
		Reason:   fmt.Sprintf("score=%d category=%s source=%s", score, best.Category, best.Source),
		Verdicts: verdicts,
	}

	// ── Safety invariant §1: dry-run must enforce nothing and write nothing ────
	if op == "dry_ban" {
		slog.InfoContext(ctx, "decision: dry_ban (armed=false)",
			"ip", ip, "would_strike", nextStrike, "would_ttl", ttl)
		return act, nil
	}

	// ── Safety invariant §1: rate limit enforced before every real ban ─────────
	if err := e.checkRateLimit(); err != nil {
		return sdk.Action{}, err
	}

	if err := e.store.RecordStrike(ctx, act); err != nil {
		return sdk.Action{}, fmt.Errorf("decision: RecordStrike: %w", err)
	}

	return act, nil
}

// isAllowlisted reports whether ip is covered by any entry in the static allowlist.
// The static allowlist is built once in New() from policy.Allowlist + AdminCIDRs +
// the SSH peer at startup; after construction it is read-only (no lock needed).
func (e *Engine) isAllowlisted(ip netip.Addr) bool {
	for _, p := range e.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// checkRateLimit increments the ban counter for the current 1-minute window and
// returns ErrRateLimited when the configured cap is exceeded.
// Uses a fixed-window counter reset after one minute.
func (e *Engine) checkRateLimit() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if time.Since(e.windowStart) > time.Minute {
		e.windowStart = time.Now()
		e.bansInWin = 0
	}
	e.bansInWin++
	if e.bansInWin > e.policy.MaxBansPerMinute {
		return ErrRateLimited
	}
	return nil
}

// buildAllowlist parses policy.Allowlist, policy.AdminCIDRs, and the SSH peer
// from SSH_CLIENT into a slice of netip.Prefix used for allowlist lookup.
func buildAllowlist(policy *config.Policy) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix

	for _, s := range policy.Allowlist {
		p, err := parsePrefixOrAddr(s)
		if err != nil {
			return nil, fmt.Errorf("decision: allowlist entry %q: %w", s, err)
		}
		prefixes = append(prefixes, p)
	}

	for _, s := range policy.AdminCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("decision: admin_cidrs entry %q: %w", s, err)
		}
		prefixes = append(prefixes, p)
	}

	// Anti-lockout: add the SSH peer present at daemon startup.
	if peer := sshClientIP(); peer.IsValid() {
		prefixes = append(prefixes, netip.PrefixFrom(peer, peer.BitLen()))
	}

	return prefixes, nil
}

// parsePrefixOrAddr accepts a bare IP ("1.2.3.4") or a CIDR ("10.0.0.0/8")
// and returns the equivalent netip.Prefix.
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP address or CIDR %q", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// sshClientIP returns the client IP from the SSH_CLIENT environment variable.
// OpenSSH sets SSH_CLIENT to "IP srcport dstport" for each session.
// Returns the zero Addr if SSH_CLIENT is unset or cannot be parsed.
func sshClientIP() netip.Addr {
	v := os.Getenv("SSH_CLIENT")
	if v == "" {
		return netip.Addr{}
	}
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(fields[0])
	if err != nil {
		return netip.Addr{}
	}
	return ip
}
