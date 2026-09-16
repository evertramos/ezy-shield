// SPDX-License-Identifier: AGPL-3.0-only

package decision

// Rising-edge audit for notify_only (issue #649). The observe band has no
// equivalent of the active-ban guard: while a rule stays saturated, every
// evaluation used to append its own notify_only audit row — 135 rows in one
// minute for one IP on the dogfood host, one per event above the threshold.
// The engine now remembers, per IP, the last rule it audited a notify_only
// for and when; a repeat of the same rule inside notifyEdgeWindow still
// RETURNS Op="notify_only" (the daemon's notifier dedup, the metrics and the
// live stream see every event exactly as before) but writes no row. A
// different rule, an elapsed window, or a strike opens a fresh edge.
//
// Nothing here changes a decision: the state is consulted only after every
// guard has run and only decides whether the Audit call is made.

import (
	"net/netip"
	"strings"
	"time"
)

// notifyEdgeWindow is how long a notify_only audit row stands in for the
// repeats that follow it for the same (ip, rule). sdk.Verdict carries no rule
// window, so this is a constant matching the default rule tier (60 s): one
// row per minute while a scanner stays saturated — the same cadence the
// dogfood host showed as 135 rows.
const notifyEdgeWindow = 60 * time.Second

// notifyEdgeMaxEntries caps the per-IP edge map. One entry per IP (the last
// rule and its time), so 10 000 distinct observe-band clients inside one
// window is the bound; beyond it expired entries are swept and, if none
// expired, the oldest edge is dropped — dropping an edge can only cause one
// extra audit row, never a missing decision.
const notifyEdgeMaxEntries = 10_000

// notifyRuleMaxLen bounds the rule identity kept per entry. Rule verdicts
// spell "rule/<name>: …" and are short; an AI or plugin verdict may carry a
// long free-text Reason without a ':' and must not inflate the entry.
const notifyRuleMaxLen = 128

// notifyEdge is the last audited notify_only for one IP.
type notifyEdge struct {
	rule string
	at   time.Time
}

// notifyRuleID returns the stable rule identity of a verdict Reason: the
// text before the first ':' — "rule/http_scanner_503" from
// "rule/http_scanner_503: 56 events in 1m0s (threshold 15)" — so the rising
// count in the suffix does not defeat the edge. A Reason without ':' is used
// whole, truncated to notifyRuleMaxLen.
func notifyRuleID(reason string) string {
	if i := strings.IndexByte(reason, ':'); i >= 0 {
		reason = reason[:i]
	}
	if len(reason) > notifyRuleMaxLen {
		reason = reason[:notifyRuleMaxLen]
	}
	// Clone: a substring shares the caller's backing array, so a long AI or
	// plugin Reason would otherwise be retained whole for the window.
	return strings.Clone(reason)
}

// notifyEdgeRising reports whether a notify_only for (ip, rule) at now is a
// rising edge — the first for that rule on that IP, or the first since the
// window elapsed or the edge was cleared — and records it as the new edge
// when it is. ip is already Unmap()ed by Decide, so both spellings of one
// client share an entry.
func (e *Engine) notifyEdgeRising(ip netip.Addr, rule string, now time.Time) bool {
	e.notifyMu.Lock()
	defer e.notifyMu.Unlock()
	if e.notifyEdges == nil {
		e.notifyEdges = make(map[netip.Addr]notifyEdge)
	}
	prev, ok := e.notifyEdges[ip]
	if ok && prev.rule == rule && now.Sub(prev.at) < notifyEdgeWindow {
		return false
	}
	if !ok && len(e.notifyEdges) >= notifyEdgeMaxEntries {
		e.evictNotifyEdgesLocked(now)
	}
	e.notifyEdges[ip] = notifyEdge{rule: rule, at: now}
	return true
}

// evictNotifyEdgesLocked drops every expired edge and, when none has
// expired, the oldest one, so an insert always has room. Called with
// notifyMu held and only when the map is at capacity.
func (e *Engine) evictNotifyEdgesLocked(now time.Time) {
	dropped := false
	for ip, edge := range e.notifyEdges {
		if now.Sub(edge.at) >= notifyEdgeWindow {
			delete(e.notifyEdges, ip)
			dropped = true
		}
	}
	if dropped {
		return
	}
	// Nothing expired: drop one arbitrary entry (map iteration order is
	// randomised) instead of scanning for the oldest — dropping any edge
	// costs at most one extra audit row, and this keeps a full map O(1)
	// per insert under a client rotating addresses.
	for ip := range e.notifyEdges {
		delete(e.notifyEdges, ip)
		return
	}
}

// clearNotifyEdge forgets ip's edge: after a strike the next observe-band
// evaluation is a new episode and must be audited, and after a failed Audit
// the next evaluation must retry rather than lose the window's row.
func (e *Engine) clearNotifyEdge(ip netip.Addr) {
	e.notifyMu.Lock()
	defer e.notifyMu.Unlock()
	delete(e.notifyEdges, ip)
}
