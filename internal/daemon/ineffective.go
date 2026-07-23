package daemon

// ineffective.go — daemon-side delivery of the ban_ineffective diagnostics
// (ADR-0009 §4, issue #146). The Daemon implements decision.Diagnostics:
// every firing becomes a stream event, and notifications are deduplicated
// SYSTEMICALLY — broken enforcement fires for many IPs at once (CDN in
// front, enforcer down, real-IP parsing missing), so the operator gets one
// "enforcement looks broken" alert per window, not one per IP. The remedy
// is always systemic (edge enforcement / real-IP parsing / enforcer
// repair), never per-IP sentencing.

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// defaultIneffNotifyWindow is the systemic dedup window: at most one
// ban_ineffective notification per window, aggregating everything else.
const defaultIneffNotifyWindow = 15 * time.Minute

// ineffDedup holds the notification dedup state. Counters are per-window;
// the stream events and per-IP WARN logs are never deduplicated — only the
// operator-facing notification is.
type ineffDedup struct {
	mu          sync.Mutex
	window      time.Duration // 0 = defaultIneffNotifyWindow
	windowStart time.Time
	suppressed  int // firings swallowed since the last notification
}

// shouldNotify reports whether a notification may be sent now, and if not,
// how many firings (including this one) have been aggregated since the last
// one. When a new window opens it also returns the count carried over from
// the previous window so the next alert can say "N more IPs since the last
// alert".
func (dd *ineffDedup) shouldNotify(now time.Time) (send bool, carried int) {
	dd.mu.Lock()
	defer dd.mu.Unlock()
	w := dd.window
	if w <= 0 {
		w = defaultIneffNotifyWindow
	}
	if dd.windowStart.IsZero() || now.Sub(dd.windowStart) >= w {
		carried = dd.suppressed
		dd.windowStart = now
		dd.suppressed = 0
		return true, carried
	}
	dd.suppressed++
	return false, dd.suppressed
}

// BanIneffective implements decision.Diagnostics. Every field in d is
// engine-derived (IPs, strikes, counts) — no raw log content (Hard Rule §4)
// — so it is forwarded to the notifier verbatim.
func (d *Daemon) BanIneffective(ctx context.Context, diag decision.BanIneffectiveDiag) {
	ladder := fmt.Sprintf("strike %d/%d — next rungs: %s", diag.Strike, diag.LadderLen, diag.NextRungs)
	reason := fmt.Sprintf("%s; %d events ≥%ds after the ban (total suppressed: %d)",
		ladder, diag.EventsAfterGrace, diag.GraceSeconds, diag.TotalSuppressed)

	// Stream event: one per firing, never deduplicated — subscribers do
	// their own aggregation.
	d.publishActionEvent("ban_ineffective", diag.IP.String(), diag.Strike, 0, reason, "engine")

	if d.notifier == nil {
		return
	}
	send, carried := d.ineffDedup.shouldNotify(time.Now())
	if !send {
		slog.DebugContext(ctx, "daemon: ban_ineffective notification deduplicated",
			"ip", diag.IP, "suppressed_in_window", carried)
		return
	}
	body := fmt.Sprintf(
		"Traffic from %s is flowing DESPITE an active ban (%s).\n"+
			"This signal is systemic — likely causes: a CDN/proxy in front of the server "+
			"(local bans never see the client IP), missing real-IP parsing, or a broken enforcer.\n"+
			"Fix the enforcement path (edge enforcement, real-IP config, enforcer health) — "+
			"per-IP sentencing will not help.",
		diag.IP, reason)
	if carried > 0 {
		body += fmt.Sprintf("\n%d additional firing(s) were aggregated since the previous alert.", carried)
	}
	if err := d.notifier.Send(ctx, sdk.Notification{
		Severity: "critical",
		Title:    fmt.Sprintf("[ban_ineffective] enforcement looks broken (%s)", diag.IP),
		Body:     body,
	}); err != nil {
		slog.ErrorContext(ctx, "daemon: ban_ineffective notification failed", "err", err)
	}
}

// BanIneffectivePermanent implements decision.Diagnostics. Deliberately NOT
// deduplicated: promoting to permanent an IP whose bans were ineffective is
// the one case that must never pass silently (ADR-0009 §4), and it is rare
// by construction (requires a full ladder walk plus a prior firing).
func (d *Daemon) BanIneffectivePermanent(ctx context.Context, ip netip.Addr, strike int) {
	reason := fmt.Sprintf("promoting to PERMANENT at strike %d an IP whose previous ban was ineffective", strike)
	d.publishActionEvent("ban_ineffective_permanent", ip.String(), strike, 0, reason, "engine")

	if d.notifier == nil {
		return
	}
	if err := d.notifier.Send(ctx, sdk.Notification{
		Severity: "critical",
		Title:    fmt.Sprintf("[ban_ineffective_permanent] %s promoted to permanent while enforcement looks broken", ip),
		Body: reason + ".\nThe permanent ban will look 'resolved forever' while traffic keeps flowing. " +
			"Verify the enforcement path before trusting this ban (edge enforcement / real-IP parsing / enforcer health).",
	}); err != nil {
		slog.ErrorContext(ctx, "daemon: ban_ineffective_permanent notification failed", "err", err)
	}
}
