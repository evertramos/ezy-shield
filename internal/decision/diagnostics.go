package decision

// diagnostics.go — delivery hook for enforcement-anomaly signals
// (ADR-0009 §4, issue #146). The engine detects ban_ineffective and the
// pre-permanent alert; HOW they reach the operator (stream events,
// deduplicated notifications) is the daemon's concern, injected here so the
// decision package stays free of notify/eventbus dependencies.

import (
	"context"
	"net/netip"
)

// BanIneffectiveDiag is the derived ladder context of one ban_ineffective
// firing. Every field is engine-derived (IP, counts, strike positions) —
// no raw log content ever appears here (Hard Rule §4), so implementations
// may forward it verbatim to notifiers.
type BanIneffectiveDiag struct {
	IP netip.Addr
	// Strike is the active ban's rung; LadderLen the policy ladder size.
	Strike, LadderLen int
	// NextRungs is the human summary of the remaining rungs
	// (e.g. "7d, permanent" or "(already at top)").
	NextRungs string
	// EventsAfterGrace / TotalSuppressed are the per-ban suppression
	// counters at firing time; GraceSeconds is the configured grace.
	EventsAfterGrace, TotalSuppressed int
	GraceSeconds                      int
}

// Diagnostics receives enforcement-anomaly signals from the engine.
// Implementations run synchronously on the decision path and must tolerate
// concurrent calls; they may perform I/O (the daemon sends a notification
// inline, like the rest of dispatch), but every firing is once-per-ban and
// notification sends are deduplicated, so the amortized cost stays
// negligible. A nil Diagnostics is valid: the engine then only logs,
// exactly the pre-#146 behavior.
type Diagnostics interface {
	// BanIneffective fires exactly once per ban (the store's
	// compare-and-set guarantees it) when suppressed post-grace events
	// cross the policy threshold: traffic is flowing despite an active ban.
	BanIneffective(ctx context.Context, d BanIneffectiveDiag)
	// BanIneffectivePermanent fires when the ladder promotes to permanent
	// an IP that had an ineffective ban before — the one case that must
	// never pass silently (ADR-0009 §4).
	BanIneffectivePermanent(ctx context.Context, ip netip.Addr, strike int)
}

// SetDiagnostics injects the delivery sink. Call before the engine starts
// serving concurrent Decide calls (the daemon does it during construction);
// the field is read without synchronization afterwards.
func (e *Engine) SetDiagnostics(d Diagnostics) {
	e.diag = d
}
