// Package notify fans-out alert messages to configured notification channels
// (Telegram, email, ...) with per-channel rate limiting and a global dedup window.
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	// DefaultRateLimitPerMinute is used when the config omits rate_limit_per_minute.
	DefaultRateLimitPerMinute = 5
	// DefaultDedupWindowSec is used when the config omits dedup_window_sec.
	DefaultDedupWindowSec = 600
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
}

// notifyChannel pairs a Notifier with its severity filter and rate limiter.
type notifyChannel struct {
	n        sdk.Notifier
	severity map[string]bool // nil = all severities accepted
	rl       *rateLimiter
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
	channels := make([]*notifyChannel, 0, len(notifiers))
	for _, n := range notifiers {
		sev := severities[n.Name()]
		channels = append(channels, newChannel(n, maxPerMinute, sev))
	}
	return &Dispatcher{
		channels:    channels,
		dedup:       make(map[string]time.Time),
		dedupWindow: dedupWindow,
		now:         now,
	}
}

func newChannel(n sdk.Notifier, maxPerMinute int, severity []string) *notifyChannel {
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
		rl:       newRateLimiter(maxPerMinute, time.Minute),
	}
}

// Register adds a Notifier at runtime with a per-channel rate limit and optional severity filter.
func (d *Dispatcher) Register(n sdk.Notifier, maxPerMinute int, severity []string) {
	if maxPerMinute <= 0 {
		maxPerMinute = DefaultRateLimitPerMinute
	}
	d.channels = append(d.channels, newChannel(n, maxPerMinute, severity))
}

// Send fans out msg to every channel that accepts its severity and has not
// hit its rate limit. A notification is suppressed entirely (across all channels)
// if the same IP+reason was seen within the dedup window.
func (d *Dispatcher) Send(ctx context.Context, msg sdk.Notification) error {
	key := dedupKey(msg)
	if !d.checkDedup(key) {
		slog.DebugContext(ctx, "notify: suppressed duplicate", "key", key)
		return nil
	}

	var errs []string
	for _, ch := range d.channels {
		if !ch.acceptsSeverity(msg.Severity) {
			continue
		}
		if !ch.rl.Allow() {
			slog.WarnContext(ctx, "notify: rate limit reached, dropping notification",
				"channel", ch.n.Name(), "severity", msg.Severity)
			continue
		}
		if err := ch.n.Send(ctx, msg); err != nil {
			slog.ErrorContext(ctx, "notify: send error", "channel", ch.n.Name(), "err", err)
			errs = append(errs, fmt.Sprintf("%s: %v", ch.n.Name(), err))
		}
	}
	if len(errs) == 1 {
		return fmt.Errorf("notify: %s", errs[0])
	}
	if len(errs) > 1 {
		return fmt.Errorf("notify: multiple errors: %v", errs)
	}
	return nil
}

// checkDedup returns true (allow) when the key has not been seen within the
// dedup window, and records the key. Returns false (suppress) otherwise.
func (d *Dispatcher) checkDedup(key string) bool {
	d.dedupMu.Lock()
	defer d.dedupMu.Unlock()
	now := d.now()
	if last, ok := d.dedup[key]; ok && now.Sub(last) < d.dedupWindow {
		return false
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
	return true
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

// rateLimiter implements a sliding-window rate limiter.
type rateLimiter struct {
	mu      sync.Mutex
	maxN    int
	window  time.Duration
	history []time.Time
}

func newRateLimiter(maxN int, window time.Duration) *rateLimiter {
	return &rateLimiter{maxN: maxN, window: window}
}

// Allow returns true and records the attempt if within the rate limit.
func (r *rateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
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
