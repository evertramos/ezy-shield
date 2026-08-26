// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// notify_only suppression (issue #421). A sustained scanner below
// ban_threshold used to generate a notification on every burst for hours —
// 691 notify_only rows in a 2-day audit window, dominated by a handful of
// repeat scanners. Suppression is keyed by (IP, rule category): the first
// occurrence notifies immediately, repeats within the window are counted,
// and the count is folded into ONE summary notification once the window
// closes. Only notifications are suppressed — audit_log rows are written by
// the decision engine before this layer and stay complete.

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// defaultNotifyOnlyWindow is the suppression window when config omits
// notify.notify_only_window_sec. One hour: the audited scanners burst every
// few minutes for hours, so minute-scale windows barely dent the volume.
const defaultNotifyOnlyWindow = time.Hour

// notifySuppressor tracks per-(IP, rule) notify_only windows.
// Safe for concurrent use.
type notifySuppressor struct {
	mu     sync.Mutex
	window time.Duration
	nowFn  func() time.Time
	seen   map[string]*suppressWindow
}

type suppressWindow struct {
	start      time.Time
	suppressed int
	lastAction sdk.Action // most recent suppressed action, for the summary body
}

func newNotifySuppressor(window time.Duration) *notifySuppressor {
	if window <= 0 {
		window = defaultNotifyOnlyWindow
	}
	return &notifySuppressor{
		window: window,
		nowFn:  time.Now,
		seen:   make(map[string]*suppressWindow),
	}
}

// suppressKey identifies a (IP, rule) stream. The rule identity is the
// top verdict's Category (the rules engine's stable per-rule label); an
// absent category falls back to the whole Reason so distinct causes never
// collapse into one stream.
func suppressKey(a sdk.Action) string {
	rule := ""
	for _, v := range a.Verdicts {
		if v.Category != "" {
			rule = v.Category
			break
		}
	}
	if rule == "" {
		rule = a.Reason
	}
	return a.IP.String() + "|" + rule
}

// admit decides the fate of one notify_only action: send=true means notify
// now (first occurrence of its window). When a previous window for the same
// key just closed with suppressed repeats, its summary is returned alongside
// so the caller can emit it before the fresh notification.
func (s *notifySuppressor) admit(a sdk.Action) (send bool, summary *sdk.Notification) {
	now := s.nowFn()
	key := suppressKey(a)

	s.mu.Lock()
	defer s.mu.Unlock()

	w, ok := s.seen[key]
	if ok && now.Sub(w.start) < s.window {
		w.suppressed++
		w.lastAction = a
		return false, nil
	}
	if ok && w.suppressed > 0 {
		summary = s.summaryLocked(key, w)
	}
	s.seen[key] = &suppressWindow{start: now}
	return true, summary
}

// flush emits summaries for every window that has closed with suppressed
// repeats and forgets idle keys. Called periodically by the daemon so a
// scanner that STOPS still gets its trailing summary (admit alone only
// settles a window when the same key shows up again).
func (s *notifySuppressor) flush() []sdk.Notification {
	now := s.nowFn()
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []sdk.Notification
	for key, w := range s.seen {
		if now.Sub(w.start) < s.window {
			continue
		}
		if w.suppressed > 0 {
			out = append(out, *s.summaryLocked(key, w))
		}
		delete(s.seen, key)
	}
	return out
}

// summaryLocked builds the fold-up notification for a closed window.
// Caller holds s.mu.
func (s *notifySuppressor) summaryLocked(key string, w *suppressWindow) *sdk.Notification {
	a := w.lastAction
	return &sdk.Notification{
		Severity: "info",
		Title:    fmt.Sprintf("[notify_only] %s — %d repeats suppressed", a.IP, w.suppressed),
		Body: fmt.Sprintf("%d further notify_only events for %s were suppressed over %s (last: %s). "+
			"Audit log rows are complete — only notifications were folded.",
			w.suppressed, key, s.window, a.Reason),
		Action: &a,
	}
}

// runNotifySuppressFlush periodically emits trailing summaries for closed
// windows. Ticks at a quarter of the window so a summary lags a stopped
// scanner by at most ~1.25 windows.
func (d *Daemon) runNotifySuppressFlush(ctx context.Context) {
	if d.notifySup == nil || d.notifier == nil {
		return
	}
	tick := d.notifySup.window / 4
	if tick < time.Second {
		tick = time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, msg := range d.notifySup.flush() {
				if err := d.notifier.Send(ctx, msg); err != nil {
					slog.ErrorContext(ctx, "daemon: notify_only summary send failed", "err", err)
				}
			}
		}
	}
}
