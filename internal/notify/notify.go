// SPDX-License-Identifier: AGPL-3.0-only

// Package notify fans-out alert messages to configured notification channels
// (Telegram, email, ...) with per-channel rate limiting and a global dedup window.
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	// DefaultRateLimitPerMinute is used when the config omits rate_limit_per_minute.
	DefaultRateLimitPerMinute = 5
	// DefaultDedupWindowSec is used when the config omits dedup_window_sec.
	DefaultDedupWindowSec = 600
	// CriticalRateLimitPerMinute is the per-channel quota reserved for
	// critical notifications (issue #613). Criticals do not compete with
	// warnings for rate_limit_per_minute: five "[ban] … strike 1" warnings
	// must never silence the one "enforcement DEGRADED" alert that fires
	// exactly when enforcement breaks. The cap only bounds a runaway.
	CriticalRateLimitPerMinute = 20
	// SeverityCritical is the severity that uses the reserved quota.
	SeverityCritical = "critical"
)

// Dispatcher fans-out Notifications to all registered Notifiers.
// It applies per-channel rate limiting and a global dedup window that
// suppresses the same IP+reason pair for dedupWindow.
type Dispatcher struct {
	channels    []*notifyChannel
	dedupMu     sync.Mutex
	dedup       map[string]time.Time
	dedupWindow time.Duration
	now         func() time.Time // injectable for tests
	host        string           // stamped onto each notification (issue #667)
	// dropped counts sends suppressed by a rate limiter (per channel-message
	// pair). Observable through Dropped() and the daemon's metrics (issue
	// #613): a silent drop is how an outage went unreported.
	dropped atomic.Int64
}

// notifyChannel pairs a Notifier with its severity filter and rate limiters:
// the configured one for info/warn and a reserved one for critical.
type notifyChannel struct {
	n        sdk.Notifier
	severity map[string]bool // nil = all severities accepted
	rl       *rateLimiter
	rlCrit   *rateLimiter
}

// New builds a Dispatcher.
// maxPerMinute is the per-channel send quota (default DefaultRateLimitPerMinute).
// dedupWindow is the suppression window for repeat IP+reason pairs (default 10 min).
// severities maps Notifier.Name() → accepted severity levels; nil or missing key = all.
func New(
	notifiers []sdk.Notifier,
	maxPerMinute int,
	dedupWindow time.Duration,
	severities map[string][]string,
) *Dispatcher {
	return NewWithClock(notifiers, maxPerMinute, dedupWindow, severities, time.Now)
}

// NewWithClock is like New but accepts a clock function for deterministic testing.
func NewWithClock(
	notifiers []sdk.Notifier,
	maxPerMinute int,
	dedupWindow time.Duration,
	severities map[string][]string,
	now func() time.Time,
) *Dispatcher {
	if maxPerMinute <= 0 {
		maxPerMinute = DefaultRateLimitPerMinute
	}
	if dedupWindow <= 0 {
		dedupWindow = time.Duration(DefaultDedupWindowSec) * time.Second
	}
	host, _ := os.Hostname() // best-effort; empty is fine
	d := &Dispatcher{
		dedup:       make(map[string]time.Time),
		dedupWindow: dedupWindow,
		now:         now,
		host:        host,
	}
	d.channels = make([]*notifyChannel, 0, len(notifiers))
	for _, n := range notifiers {
		sev := severities[n.Name()]
		d.channels = append(d.channels, d.newChannel(n, maxPerMinute, sev))
	}
	return d
}

func (d *Dispatcher) newChannel(n sdk.Notifier, maxPerMinute int, severity []string) *notifyChannel {
	var sevMap map[string]bool
	if len(severity) > 0 {
		sevMap = make(map[string]bool, len(severity))
		for _, s := range severity {
			sevMap[s] = true
		}
	}
	return &notifyChannel{
		n:        n,
		severity: sevMap,
		rl:       newRateLimiter(maxPerMinute, time.Minute, d.now),
		rlCrit:   newRateLimiter(CriticalRateLimitPerMinute, time.Minute, d.now),
	}
}

// Register adds a Notifier at runtime with a per-channel rate limit and optional severity filter.
func (d *Dispatcher) Register(n sdk.Notifier, maxPerMinute int, severity []string) {
	if maxPerMinute <= 0 {
		maxPerMinute = DefaultRateLimitPerMinute
	}
	d.channels = append(d.channels, d.newChannel(n, maxPerMinute, severity))
}

// Dropped returns how many channel deliveries a rate limiter suppressed
// since the dispatcher was created.
func (d *Dispatcher) Dropped() int64 { return d.dropped.Load() }

// AcceptsCritical reports whether at least one channel forwards critical
// notifications — the operator's only signal for an enforcement outage.
func (d *Dispatcher) AcceptsCritical() bool {
	for _, ch := range d.channels {
		if ch.acceptsSeverity(SeverityCritical) {
			return true
		}
	}
	return false
}

// Send fans out msg to every channel that accepts its severity and has not
// hit its rate limit. A notification is suppressed entirely (across all
// channels) if the same IP+reason was seen within the dedup window.
//
// Criticals use each channel's reserved quota (CriticalRateLimitPerMinute)
// instead of rate_limit_per_minute, so a burst of warnings cannot starve
// them (issue #613). The dedup key is recorded only once at least one
// channel accepted the message: a delivery nobody received must not
// suppress the same alert when the quota frees up.
func (d *Dispatcher) Send(ctx context.Context, msg sdk.Notification) error {
	if msg.Host == "" {
		msg.Host = d.host // stamp the source host once, centrally (issue #667)
	}
	key := dedupKey(msg)
	// Claim the dedup window BEFORE sending, under the lock, so two
	// concurrent sends of the same message (dispatch and the deferred retry
	// both alerting an enforcer failure) cannot both pass the check while
	// one is mid-flight; the claim is released below if no channel
	// delivered, so a rate-limited or failed send can be retried (#613).
	claim, ok := d.claimDedup(key)
	if !ok {
		slog.DebugContext(ctx, "notify: suppressed duplicate", "key", key)
		return nil
	}

	var errs []string
	delivered := false
	for _, ch := range d.channels {
		if !ch.acceptsSeverity(msg.Severity) {
			continue
		}
		rl := ch.rl
		if msg.Severity == SeverityCritical {
			rl = ch.rlCrit
		}
		if !rl.Allow() {
			d.dropped.Add(1)
			slog.WarnContext(ctx, "notify: rate limit reached, dropping notification",
				"channel", ch.n.Name(), "severity", msg.Severity, "dropped_total", d.dropped.Load())
			continue
		}
		if err := ch.n.Send(ctx, msg); err != nil {
			slog.ErrorContext(ctx, "notify: send error", "channel", ch.n.Name(), "err", err)
			errs = append(errs, fmt.Sprintf("%s: %v", ch.n.Name(), err))
			continue
		}
		delivered = true
	}
	if !delivered {
		d.releaseDedup(key, claim)
	}
	if len(errs) == 1 {
		return fmt.Errorf("notify: %s", errs[0])
	}
	if len(errs) > 1 {
		return fmt.Errorf("notify: multiple errors: %v", errs)
	}
	return nil
}

// claimDedup atomically checks and claims the dedup window for key: false
// when key was delivered (or is being delivered) within the window;
// otherwise the window is stamped now and the stamp returned so the caller
// can release it if nothing is delivered.
func (d *Dispatcher) claimDedup(key string) (time.Time, bool) {
	d.dedupMu.Lock()
	defer d.dedupMu.Unlock()
	now := d.now()
	if last, ok := d.dedup[key]; ok && now.Sub(last) < d.dedupWindow {
		return time.Time{}, false
	}
	d.dedup[key] = now
	// GC: prune expired entries when the map grows large to bound memory.
	if len(d.dedup) > 10000 {
		cutoff := now.Add(-d.dedupWindow)
		for k, t := range d.dedup {
			if t.Before(cutoff) {
				delete(d.dedup, k)
			}
		}
	}
	return now, true
}

// releaseDedup gives the window back when no channel delivered — only if
// the stamp is still ours (a newer claim by a concurrent sender stands).
func (d *Dispatcher) releaseDedup(key string, claim time.Time) {
	d.dedupMu.Lock()
	defer d.dedupMu.Unlock()
	if last, ok := d.dedup[key]; ok && last.Equal(claim) {
		delete(d.dedup, key)
	}
}

func (ch *notifyChannel) acceptsSeverity(sev string) bool {
	if ch.severity == nil {
		return true
	}
	return ch.severity[sev]
}

// dedupKey builds the suppression key from a Notification.
// For action-triggered notifications the key is IP+reason (attacker-bound).
// For system notifications it is severity+title (usually daemon-generated).
func dedupKey(msg sdk.Notification) string {
	if msg.Action != nil && msg.Action.IP.IsValid() {
		return "ip:" + msg.Action.IP.String() + "|" + msg.Action.Reason
	}
	return "sys:" + msg.Severity + "|" + msg.Title
}

// rateLimiter implements a sliding-window rate limiter on the dispatcher's
// clock (injectable, so quota recovery is testable without sleeping).
type rateLimiter struct {
	mu      sync.Mutex
	maxN    int
	window  time.Duration
	now     func() time.Time
	history []time.Time
}

func newRateLimiter(maxN int, window time.Duration, now func() time.Time) *rateLimiter {
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{maxN: maxN, window: window, now: now}
}

// Allow returns true and records the attempt if within the rate limit.
func (r *rateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	cutoff := now.Add(-r.window)
	// Slide the window: remove entries older than the cutoff.
	start := 0
	for start < len(r.history) && r.history[start].Before(cutoff) {
		start++
	}
	r.history = r.history[start:]
	if len(r.history) >= r.maxN {
		return false
	}
	r.history = append(r.history, now)
	return true
}
