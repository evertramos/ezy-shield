// Package decision is the safety-critical policy engine that converts Verdicts
// into enforceable Actions. It enforces allowlists, anti-lockout checks, strike
// escalation, global rate limiting, and dry-run mode.
//
// Safety invariants (AGENTS.md Hard Rule §1):
//   - Allowlist always wins: checked before any other logic, unbypassable.
//   - Anti-lockout: active SSH peers are re-derived before every ban, from
//     SSH_CLIENT (interactive) and /proc/net/tcp{,6} (systemd — issue #175).
//   - Dry-run default: Op="dry_ban", nothing is ever enforced, until
//     policy.Armed=true. Dry-run mirrors armed semantics (ADR-0009 §5):
//     strikes and simulated bans ARE recorded so escalation, suppression,
//     and the rate-limit cap behave exactly as production would — but a
//     simulated ban never reaches an enforcer.
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
	// GetBanInfo returns when ip's active ban was applied, at which strike,
	// and whether it is a simulated dry-run ban (ADR-0009 §5). found is false
	// when ip has no active ban. The engine calls this before GetStrikeCount
	// to suppress redundant strike/enforcer writes for already-banned IPs.
	GetBanInfo(ctx context.Context, ip netip.Addr) (bannedAt time.Time, strike int, dryRun bool, found bool, err error)
	// RecordSuppressed increments ip's per-ban suppression counters and
	// returns the updated totals plus whether ban_ineffective already fired
	// for this ban. Zero counts when ip has no active ban row (expiry race).
	RecordSuppressed(ctx context.Context, ip netip.Addr, afterGrace bool) (total, afterGraceCount int, fired bool, err error)
	// MarkBanIneffective flags ip's active ban as diagnosed and records the
	// permanent had-ineffective mark on the offender. Returns true only for
	// the caller that transitioned the flag (fire-once guarantee).
	MarkBanIneffective(ctx context.Context, ip netip.Addr) (bool, error)
	// HadIneffectiveBan reports whether ip ever had a ban marked ineffective;
	// survives ban expiry and daemon restarts.
	HadIneffectiveBan(ctx context.Context, ip netip.Addr) (bool, error)
	// BumpLastSeen updates offenders.last_seen for ip without recording a strike.
	BumpLastSeen(ctx context.Context, ip netip.Addr) error
	// GetStrikeCount returns the cumulative strike count for ip (0 if never seen).
	GetStrikeCount(ctx context.Context, ip netip.Addr) (int, error)
	// LastStrike returns the recording time and TTL of ip's most recent strike;
	// found is false when ip has no strike history. The engine uses it to bound
	// the escalation rate-limit exemption to recently-ended bans (ADR-0009).
	LastStrike(ctx context.Context, ip netip.Addr) (recordedAt time.Time, ttl time.Duration, found bool, err error)
	// RecordStrike persists a ban strike and updates bans_active + audit_log.
	RecordStrike(ctx context.Context, a sdk.Action) error
	// Audit appends a record to the append-only audit_log without recording a strike.
	Audit(ctx context.Context, a sdk.Action) error
}

// Engine converts Verdicts into Actions according to policy.
// It is safe for concurrent use. Suppression state for the ban_ineffective
// diagnostic (ADR-0009) lives in the store, on the ban row itself — nothing
// here grows with offender count, and the diagnostic history survives
// daemon restarts.
type Engine struct {
	policy *config.Policy
	store  Store
	allow  []netip.Prefix // static allowlist built at construction time

	mu          sync.Mutex
	bansInWin   int
	windowStart time.Time

	// sshPeers caches kernel-derived SSH peers (/proc/net/tcp{,6}) for the
	// anti-lockout checks — the detection path that works under systemd,
	// where SSH_CLIENT does not exist (issue #175).
	sshPeers sshPeerCache
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

	// ── Safety invariant §1: anti-lockout — re-derive SSH peers before every ban ─
	// Peers come from SSH_CLIENT (interactive contexts) AND from the kernel's
	// established-connection table (/proc/net/tcp{,6}) — the source that
	// exists under systemd, where the env var does not (issue #175).
	for _, peer := range e.activeSSHPeers() {
		if peer == ip {
			slog.WarnContext(ctx, "decision: anti-lockout — refusing to ban active SSH peer", "ip", ip)
			act := sdk.Action{IP: ip, Op: "record", Reason: "anti-lockout: active SSH peer", Verdicts: verdicts}
			if err := e.store.Audit(ctx, act); err != nil {
				slog.ErrorContext(ctx, "decision: audit anti-lockout", "ip", ip, "err", err)
			}
			return act, nil
		}
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

	// ── Active-ban guard (issues #28, #29, ADR-0009) ────────────────────────
	// If the IP already has an active ban (temp or permanent), suppress the
	// strike/audit/enforcer writes. Events are counted for ban_ineffective
	// detection. Only offenders.last_seen is bumped so the IP still appears
	// as "active" in observability. bans_active remains the enforcer source
	// of truth; the Sync loop handles expiry races.
	//
	// The guard runs in BOTH modes (ADR-0009 §5: dry-run mirrors armed), with
	// one asymmetry: an ARMED engine ignores simulated (dry-run) bans. Nothing
	// is enforced for a simulated ban, so suppressing a real offense on its
	// account would leave the attacker unblocked; falling through lets the
	// strike path record a real ban, overwriting the simulated row.
	{
		bannedAt, banStrike, dryBan, banned, err := e.store.GetBanInfo(ctx, ip)
		switch {
		case err != nil:
			// Non-fatal: log and fall through to the normal strike path rather
			// than silently suppressing a verdict on a DB error.
			slog.ErrorContext(ctx, "decision: GetBanInfo failed — falling through to strike path",
				"ip", ip, "err", err)
		case banned && e.policy.IsArmed() && dryBan:
			// Leftover simulated ban from before arming — fall through.
			slog.InfoContext(ctx, "decision: ignoring simulated dry-run ban while armed",
				"ip", ip, "strike", banStrike)
		case banned:
			// Suppression path: IP is actively banned (really, or simulated
			// while in dry-run — the mirror that keeps escalation honest).
			reason := "active ban in bans_active"
			if dryBan {
				reason = "active simulated ban (dry-run)"
			}
			slog.InfoContext(ctx, "decision: already_banned — suppressing strike/enforcer",
				"ip", ip, "dry_run", dryBan)
			act := sdk.Action{IP: ip, Op: "already_banned", Reason: reason, Verdicts: verdicts}

			// Track suppressed events; ban_ineffective firing is armed-only
			// (gated inside — ADR-0009 §5).
			e.trackSuppressedEvent(ctx, ip, bannedAt, banStrike)

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
	if !e.policy.IsArmed() {
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

	// ── Safety invariant §1: dry-run must enforce nothing ─────────────────────
	// It DOES record (ADR-0009 §5): the strike, the simulated ban row
	// (dry_run=1), and the audit entry are written below through the same
	// RecordStrike path as armed mode, so dry-run shows exactly the
	// escalation production would apply. Enforcement is excluded twice over:
	// the daemon dispatches enforcer calls only for Op=="ban", and every
	// enforcer sync skips dry_run rows.
	if op == "dry_ban" {
		slog.InfoContext(ctx, "decision: dry_ban (armed=false) — recording simulated ban",
			"ip", ip, "strike", nextStrike, "ttl", ttl)
	}

	// ── Safety invariant §1: rate limit enforced before every ban ─────────────
	// Applies to dry_ban too — the cap is part of the semantics dry-run must
	// mirror: an operator observing dry-run should see the pause production
	// would take (and it bounds store writes during a runaway either way).
	// Exception (ADR-0009 §3, amended): an escalation is exempt only when the
	// previous ban ended within escalation_exempt_window — re-blocking an IP
	// that was blocked until moments ago adds no new-lockout exposure. A strike
	// count alone is NOT enough: strikes never decay, so "was banned at some
	// point" would bypass the cap forever and disable it exactly during a
	// mass-re-detection runaway. Stale escalations count like any fresh ban.
	if nextStrike > 1 && e.escalationExempt(ctx, ip) {
		slog.InfoContext(ctx, "decision: escalation exempt from rate limit — previous ban ended recently",
			"ip", ip, "strike", nextStrike)
	} else if err := e.checkRateLimit(); err != nil {
		return sdk.Action{}, err
	}

	// ── Pre-permanent alert (ADR-0009) ───────────────────────────────────────
	// If this strike promotes to permanent and the IP had ban_ineffective on a
	// prior ban, emit a louder warning — an ineffective permanent ban is the
	// worst case (operator thinks it's "resolved forever" while traffic flows).
	// The flag is read from offenders.had_ineffective, so it survives daemon
	// restarts between the ineffective ban and the promotion.
	if ttl == 0 {
		hadIneff, err := e.store.HadIneffectiveBan(ctx, ip)
		if err != nil {
			slog.ErrorContext(ctx, "decision: HadIneffectiveBan failed — pre-permanent alert skipped",
				"ip", ip, "err", err)
		} else if hadIneff {
			slog.WarnContext(ctx, "decision: ban_ineffective_permanent — promoting to permanent an IP that had ineffective bans",
				"ip", ip, "strike", nextStrike)
		}
	}

	// RecordStrike's bans_active upsert resets the per-ban suppression
	// counters — no engine-side state to clear.
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

// escalationExempt reports whether an escalation ban (strike > 1) for ip may
// skip the max_bans_per_minute cap. Exemption requires the previous ban to
// have ended within policy.EscalationExemptWindow of now.
//
// Fail-safe: every uncertain case counts against the cap — store error, no
// strike history, or a permanent last strike (a permanent ban that is no
// longer active means an operator unbanned; the re-ban is a fresh decision).
// A ban whose scheduled end is still in the future (early manual unban,
// immediate re-offense) is within the window by construction.
func (e *Engine) escalationExempt(ctx context.Context, ip netip.Addr) bool {
	recordedAt, ttl, found, err := e.store.LastStrike(ctx, ip)
	if err != nil {
		slog.ErrorContext(ctx, "decision: LastStrike failed — escalation not exempt from rate limit",
			"ip", ip, "err", err)
		return false
	}
	if !found || ttl <= 0 {
		return false
	}
	banEnd := recordedAt.Add(ttl)
	return time.Since(banEnd) <= e.policy.EscalationExemptWindow.AsDuration()
}

// trackSuppressedEvent records a suppressed event on ip's active ban and
// emits the ban_ineffective diagnostic when ≥ BanIneffectiveMinEvents arrive
// after the BanIneffectiveGrace period (ADR-0009). The counters live on the
// ban row; MarkBanIneffective's compare-and-set makes the diagnostic fire
// exactly once per ban, across concurrent calls and daemon restarts. All
// failures are non-fatal: the diagnostic must never break the suppression
// path.
func (e *Engine) trackSuppressedEvent(ctx context.Context, ip netip.Addr, bannedAt time.Time, banStrike int) {
	grace := e.policy.BanIneffectiveGrace.AsDuration()
	afterGrace := time.Since(bannedAt) >= grace

	total, afterCount, fired, err := e.store.RecordSuppressed(ctx, ip, afterGrace)
	if err != nil {
		slog.ErrorContext(ctx, "decision: RecordSuppressed failed", "ip", ip, "err", err)
		return
	}
	// ADR-0009 §5: ban_ineffective is armed-only. During a simulated ban
	// traffic is EXPECTED (nothing blocks it), not an enforcement anomaly.
	// Counters above are still recorded so dry-run observability shows what
	// a real ban would have suppressed.
	if !e.policy.IsArmed() {
		return
	}
	if !afterGrace || fired || afterCount < e.policy.BanIneffectiveMinEvents {
		return
	}

	newlyFired, err := e.store.MarkBanIneffective(ctx, ip)
	if err != nil {
		slog.ErrorContext(ctx, "decision: MarkBanIneffective failed", "ip", ip, "err", err)
		return
	}
	if !newlyFired {
		return // another Decide call won the race for this ban
	}

	// Compute ladder context for the warning
	ladderLen := len(e.policy.Strikes)
	var nextRungs string
	if banStrike < ladderLen {
		remaining := make([]string, 0, ladderLen-banStrike)
		for i := banStrike; i < ladderLen; i++ {
			ttl := e.policy.Strikes[i].TTL.AsDuration()
			if ttl == 0 {
				remaining = append(remaining, "permanent")
			} else {
				remaining = append(remaining, ttl.String())
			}
		}
		nextRungs = strings.Join(remaining, ", ")
	} else {
		nextRungs = "(already at top)"
	}

	slog.WarnContext(ctx, "decision: ban_ineffective — traffic flowing despite active ban",
		"ip", ip,
		"strike", fmt.Sprintf("%d/%d", banStrike, ladderLen),
		"next_rungs", nextRungs,
		"events_after_grace", afterCount,
		"total_suppressed", total,
		"grace_seconds", int(grace.Seconds()),
	)
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
