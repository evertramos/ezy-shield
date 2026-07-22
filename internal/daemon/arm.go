package daemon

// arm.go implements the explicit arm/disarm socket verbs (issue #228):
// a mandatory pre-flight before flipping armed, an optional daemon-side
// auto-revert window ("arm --for 1h"), and audited transitions in both
// directions. The window state lives in the store (daemon_state), so the
// revert fires even if the operator lost their session or the daemon
// restarted mid-window — that loss is the exact scenario it protects
// against.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
)

// rewriteArmedFile is config.RewriteArmed behind a var so daemon tests can
// stub the filesystem side of arm/disarm.
var rewriteArmedFile = config.RewriteArmed

// stateKeyArmWindow is the daemon_state key holding the RFC3339 deadline of
// the active auto-revert window. Absent = no window (armed is unconditional).
const stateKeyArmWindow = "arm_window_expires_at"

// Arm window bounds: shorter than a minute reverts before the operator can
// even confirm; longer than 7 days is not a "safety window" anymore.
const (
	minArmWindow = time.Minute
	maxArmWindow = 7 * 24 * time.Hour
)

// PreflightCheck is one line of the arm pre-flight report.
type PreflightCheck struct {
	// Name identifies the check: "enforcer", "admin_cidrs", "self_ban",
	// "dry_run_activity".
	Name string `json:"name"`
	// Status is "pass", "warn", or "fail".
	Status string `json:"status"`
	// Detail is a one-line human explanation.
	Detail string `json:"detail"`
}

// ArmData is the Data payload for the "arm", "arm_keep", and "disarm" verbs.
type ArmData struct {
	// Armed is the state after the operation.
	Armed bool `json:"armed"`
	// Refused is true when pre-flight failures blocked the transition.
	Refused bool `json:"refused,omitempty"`
	// Checks is the pre-flight report (arm verb only).
	Checks []PreflightCheck `json:"checks,omitempty"`
	// RevertAt is the RFC3339 auto-revert deadline when a window is active.
	RevertAt string `json:"revert_at,omitempty"`
}

// handleArm runs the pre-flight and, if it passes (or --force covers the
// failures), flips armed=true. req.For, when set, starts the auto-revert
// window. req.Peer carries the operator's own client IP (derived by the CLI
// from its SSH_CLIENT); it is used exclusively to make the self-ban check
// stricter and is never written anywhere.
func (d *Daemon) handleArm(ctx context.Context, req SocketRequest) SocketResponse {
	checks, hasFail, selfBanFail := d.runArmPreflight(ctx, req.Peer)

	// The self-ban check is never forceable: --force exists for "I know the
	// enforcer is down, arm anyway", not for "ban my own session".
	if selfBanFail {
		return armRefused(checks, "refusing to arm: your client IP would not survive enforcement (self-ban). Add it to admin_cidrs first — --force cannot bypass this check")
	}
	if hasFail && !req.Force {
		return armRefused(checks, "refusing to arm: pre-flight failed (re-run with --force to override everything except the self-ban check)")
	}

	var revertAt time.Time
	if req.For != "" {
		window, err := parseExtendedDuration(req.For)
		if err != nil {
			return SocketResponse{Error: fmt.Sprintf("invalid --for duration: %v", err)}
		}
		if window < minArmWindow || window > maxArmWindow {
			return SocketResponse{Error: fmt.Sprintf("--for must be between %s and %s, got %s", minArmWindow, maxArmWindow, window)}
		}
		revertAt = time.Now().UTC().Add(window)
	}

	reason := "operator armed via 'ezyshield arm'"
	if req.Force {
		reason += " (--force)"
	}
	if !revertAt.IsZero() {
		reason += fmt.Sprintf(" (auto-revert at %s unless confirmed with --keep)", revertAt.Format(time.RFC3339))
	}
	if err := d.setArmedState(ctx, true, "arm", reason); err != nil {
		return SocketResponse{Error: err.Error()}
	}

	data := ArmData{Armed: true, Checks: checks}
	if !revertAt.IsZero() {
		if err := d.store.SetState(ctx, stateKeyArmWindow, revertAt.Format(time.RFC3339)); err != nil {
			// Fail CLOSED on the safety window: an armed daemon whose revert
			// deadline could not be persisted would stay armed forever —
			// silently converting "arm for 1h" into "arm permanently".
			if derr := d.setArmedState(ctx, false, "arm_revert", "reverting: arm window could not be persisted"); derr != nil {
				slog.ErrorContext(ctx, "daemon: revert after window persist failure also failed", "err", derr)
			}
			return SocketResponse{Error: fmt.Sprintf("could not persist auto-revert window (reverted to dry-run): %v", err)}
		}
		data.RevertAt = revertAt.Format(time.RFC3339)
	} else {
		// An unconditional arm clears any previous window.
		if err := d.store.DeleteState(ctx, stateKeyArmWindow); err != nil {
			slog.ErrorContext(ctx, "daemon: clearing stale arm window", "err", err)
		}
	}

	raw, _ := json.Marshal(data)
	return SocketResponse{OK: true, Data: raw}
}

// handleArmKeep confirms a windowed arm: the auto-revert deadline is
// cleared and armed becomes unconditional.
func (d *Daemon) handleArmKeep(ctx context.Context) SocketResponse {
	if !d.policy.IsArmed() {
		return SocketResponse{Error: "not armed — nothing to keep"}
	}
	_, found, err := d.store.GetState(ctx, stateKeyArmWindow)
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("reading arm window: %v", err)}
	}
	if !found {
		return SocketResponse{Error: "no auto-revert window is active — already armed unconditionally"}
	}
	if err := d.store.DeleteState(ctx, stateKeyArmWindow); err != nil {
		return SocketResponse{Error: fmt.Sprintf("clearing arm window: %v", err)}
	}
	if err := d.store.AuditSystem(ctx, "arm_keep", "operator confirmed the arm window via 'ezyshield arm --keep'"); err != nil {
		slog.ErrorContext(ctx, "daemon: audit arm_keep", "err", err)
	}
	d.publishActionEvent("arm_keep", "system", 0, 0, "arm window confirmed", "operator")
	raw, _ := json.Marshal(ArmData{Armed: true})
	return SocketResponse{OK: true, Data: raw}
}

// handleDisarm flips armed=false and clears any active window. Disarming has
// no pre-flight: moving toward dry-run is always the safe direction.
func (d *Daemon) handleDisarm(ctx context.Context) SocketResponse {
	if err := d.setArmedState(ctx, false, "disarm", "operator disarmed via 'ezyshield disarm'"); err != nil {
		return SocketResponse{Error: err.Error()}
	}
	if err := d.store.DeleteState(ctx, stateKeyArmWindow); err != nil {
		slog.ErrorContext(ctx, "daemon: clearing arm window on disarm", "err", err)
	}
	raw, _ := json.Marshal(ArmData{Armed: false})
	return SocketResponse{OK: true, Data: raw}
}

func armRefused(checks []PreflightCheck, msg string) SocketResponse {
	raw, _ := json.Marshal(ArmData{Armed: false, Refused: true, Checks: checks})
	return SocketResponse{Error: msg, Data: raw}
}

// setArmedState is the single place the armed state changes: it flips the
// runtime flag, persists the change to policy.yaml (so a restart keeps it),
// appends the audit record, and publishes a stream event. op is "arm",
// "disarm", or "arm_revert".
func (d *Daemon) setArmedState(ctx context.Context, armed bool, op, reason string) error {
	if d.policyPath != "" {
		if err := rewriteArmedFile(d.policyPath, armed); err != nil {
			// Persist-first: if policy.yaml cannot be updated, do not flip
			// the runtime state either — a mismatch between file and runtime
			// is worse than a refused command.
			return fmt.Errorf("persisting armed=%v: %v", armed, err)
		}
	}
	d.policy.SetArmed(armed)
	if err := d.store.AuditSystem(ctx, op, reason); err != nil {
		slog.ErrorContext(ctx, "daemon: audit "+op, "err", err)
	}
	d.publishActionEvent(op, "system", 0, 0, reason, "operator")
	slog.WarnContext(ctx, "daemon: armed state changed", "op", op, "armed", armed, "reason", reason)
	return nil
}

// runArmPreflight evaluates every pre-flight check. hasFail reports any
// "fail" status; selfBanFail is reported separately because it can never be
// bypassed with --force.
func (d *Daemon) runArmPreflight(ctx context.Context, peer string) (checks []PreflightCheck, hasFail, selfBanFail bool) {
	add := func(name, status, detail string) {
		checks = append(checks, PreflightCheck{Name: name, Status: status, Detail: detail})
		if status == "fail" {
			hasFail = true
		}
	}

	// 1. Enforcer configured — arming without one records bans that nothing
	// enforces (the daemon would claim protection it does not deliver).
	if d.enforcer == nil {
		add("enforcer", "fail", "no enforcer configured — bans would be recorded but never enforced; configure the enforce section first")
	} else {
		add("enforcer", "pass", "enforcer configured: "+d.enforcer.Name())
	}

	// 2. admin_cidrs / allowlist protect operator access after arming.
	switch {
	case len(d.policy.AdminCIDRs) == 0 && len(d.policy.Allowlist) == 0:
		add("admin_cidrs", "fail", "admin_cidrs and allowlist are both empty — nothing protects your own access; add your management IPs to admin_cidrs")
	case len(d.policy.AdminCIDRs) == 0:
		add("admin_cidrs", "warn", "admin_cidrs is empty (allowlist has entries) — prefer admin_cidrs for operator IPs")
	default:
		add("admin_cidrs", "pass", fmt.Sprintf("admin_cidrs: %d entr%s, allowlist: %d", len(d.policy.AdminCIDRs), plural(len(d.policy.AdminCIDRs), "y", "ies"), len(d.policy.Allowlist)))
	}

	// 3. Self-ban simulation: would enforcement cut off the session issuing
	// this very command? peer comes from the CLI's SSH_CLIENT and is used
	// only to make this check stricter — never stored, never allowlisted.
	checks, selfBanFail = d.selfBanCheck(checks, peer)
	if selfBanFail {
		hasFail = true
	}

	// 4. Dry-run activity summary: what WOULD have been banned.
	simulated := 0
	if bans, err := d.store.ActiveBans(ctx); err == nil {
		for _, b := range bans {
			if b.Op == "dry_ban" {
				simulated++
			}
		}
	}
	recent := d.countRecentDryBans(ctx, 24*time.Hour)
	switch {
	case simulated == 0 && recent == 0:
		add("dry_run_activity", "warn", "no dry-run activity observed — consider running in dry-run first and reviewing what would be banned")
	default:
		add("dry_run_activity", "pass", fmt.Sprintf("last 24h: %d dry_ban decision(s); currently %d simulated ban(s) would become candidates", recent, simulated))
	}

	return checks, hasFail, selfBanFail
}

// selfBanCheck appends the self_ban check result. It fails (non-forceable)
// when the operator's client IP is known and covered by neither the policy
// allowlist/admin_cidrs nor the runtime allowlist.
func (d *Daemon) selfBanCheck(checks []PreflightCheck, peer string) ([]PreflightCheck, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(peer))
	if peer == "" || err != nil {
		checks = append(checks, PreflightCheck{
			Name: "self_ban", Status: "warn",
			Detail: "could not determine your client IP (no SSH_CLIENT?) — make sure the IP you connect from is in admin_cidrs",
		})
		return checks, false
	}

	covered := d.isRuntimeAllowlisted(addr)
	if !covered {
		for _, s := range append(append([]string{}, d.policy.Allowlist...), d.policy.AdminCIDRs...) {
			if p, perr := parsePrefixOrAddrDaemon(s); perr == nil && p.Contains(addr) {
				covered = true
				break
			}
		}
	}
	if covered {
		checks = append(checks, PreflightCheck{
			Name: "self_ban", Status: "pass",
			Detail: fmt.Sprintf("your client IP %s is covered by the allowlist", addr),
		})
		return checks, false
	}
	checks = append(checks, PreflightCheck{
		Name: "self_ban", Status: "fail",
		Detail: fmt.Sprintf("your client IP %s is NOT covered by admin_cidrs or the allowlist — arming could ban your own session (not bypassable with --force)", addr),
	})
	return checks, true
}

// countRecentDryBans counts dry_ban audit entries recorded within the last
// window. Best-effort: bounded by the audit read cap; errors count as zero.
func (d *Daemon) countRecentDryBans(ctx context.Context, window time.Duration) int {
	entries, err := d.store.ListAuditLog(ctx, 1000)
	if err != nil {
		return 0
	}
	cutoff := time.Now().UTC().Add(-window)
	n := 0
	for _, e := range entries {
		if e.Op != "dry_ban" {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, e.RecordedAt); err == nil && t.After(cutoff) {
			n++
		}
	}
	return n
}

// runArmWindow watches the auto-revert deadline and reverts to dry-run when
// it passes without an operator --keep. The interval is a field so tests can
// tighten it; reads hit the store so the loop also honours windows created
// before a restart.
func (d *Daemon) runArmWindow(ctx context.Context) {
	interval := d.armWindowTick
	if interval <= 0 {
		interval = 15 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			d.checkArmWindow(ctx, now)
		}
	}
}

// checkArmWindow reverts to dry-run when the persisted window deadline has
// passed. Also called once at startup so a daemon that was down past the
// deadline reverts immediately.
func (d *Daemon) checkArmWindow(ctx context.Context, now time.Time) {
	val, found, err := d.store.GetState(ctx, stateKeyArmWindow)
	if err != nil {
		slog.ErrorContext(ctx, "daemon: reading arm window", "err", err)
		return
	}
	if !found {
		return
	}
	if !d.policy.IsArmed() {
		// Operator disarmed through some other path (e.g. edited policy.yaml
		// while the daemon was down) — the window is stale, drop it.
		if err := d.store.DeleteState(ctx, stateKeyArmWindow); err != nil {
			slog.ErrorContext(ctx, "daemon: clearing stale arm window", "err", err)
		}
		return
	}
	deadline, err := time.Parse(time.RFC3339, val)
	if err != nil {
		// Unparseable deadline on an armed daemon: fail toward safety —
		// revert rather than staying armed on corrupted state.
		slog.ErrorContext(ctx, "daemon: corrupt arm window deadline — reverting to dry-run", "value", val, "err", err)
		deadline = now.Add(-time.Second)
	}
	if now.Before(deadline) {
		return
	}

	msg := "arm window expired without 'ezyshield arm --keep' — reverted to dry-run"
	if err := d.setArmedState(ctx, false, "arm_revert", msg); err != nil {
		// policy.yaml rewrite failed; flip the runtime state anyway — the
		// window MUST revert enforcement even if persistence is broken.
		d.policy.SetArmed(false)
		if aerr := d.store.AuditSystem(ctx, "arm_revert", msg+" (policy.yaml rewrite failed: "+err.Error()+")"); aerr != nil {
			slog.ErrorContext(ctx, "daemon: audit arm_revert", "err", aerr)
		}
		slog.ErrorContext(ctx, "daemon: arm window revert could not persist to policy.yaml", "err", err)
	}
	if err := d.store.DeleteState(ctx, stateKeyArmWindow); err != nil {
		slog.ErrorContext(ctx, "daemon: clearing arm window after revert", "err", err)
	}
	d.notifyCritical(ctx, msg)
}

// armedUntil returns the active auto-revert deadline as an RFC3339 string,
// or "" when no window is active.
func (d *Daemon) armedUntil(ctx context.Context) string {
	if !d.policy.IsArmed() {
		return ""
	}
	val, found, err := d.store.GetState(ctx, stateKeyArmWindow)
	if err != nil || !found {
		return ""
	}
	return val
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// parsePrefixOrAddrDaemon accepts a bare IP or CIDR string. Mirrors the
// decision package's parser; kept local to avoid exporting it for one call.
func parsePrefixOrAddrDaemon(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP or CIDR %q", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
