package dashboard

import (
	"sync"
	"time"
)

// loginThrottle rate-limits password guessing on /login. It is intentionally
// scoped per *username* rather than per source IP: the dashboard binds to
// loopback, so all client IPs would already collapse to 127.0.0.1 and give
// an attacker on the same box a trivial bypass. Per-account tracking also
// stops a distant attacker who bounces through many tunnels from grinding
// a single account.
//
// The rule that ships in Phase 4 is the maintainer-set default:
//
//   - 5 failed attempts inside a 60 s sliding window trip a lockout.
//   - Locked-out accounts stay locked for 60 s from the last failure.
//   - A successful login resets the window immediately.
//
// The counter is in-memory only. A daemon restart clears every lockout,
// which is intentional — the dashboard is opt-in, single-node, and the
// password bootstrap is already the maintainer's escape hatch.
const (
	throttleMaxFailures = 5
	throttleWindow      = time.Minute
	throttleLockout     = time.Minute
)

type loginThrottle struct {
	max      int
	window   time.Duration
	lockout  time.Duration
	nowClock func() time.Time

	mu       sync.Mutex
	failures map[string]*failWindow
}

// failWindow is the per-account tally. stamps holds failure times still
// inside the sliding window; lockedUntil is set to a non-zero time when a
// lockout is in force. The struct is small (a slice header + a
// time.Time) so keeping one per account is cheap.
type failWindow struct {
	stamps      []time.Time
	lockedUntil time.Time
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{
		max:      throttleMaxFailures,
		window:   throttleWindow,
		lockout:  throttleLockout,
		nowClock: time.Now,
		failures: make(map[string]*failWindow),
	}
}

// Allow reports whether an authentication attempt for username may proceed
// right now. A false return means the caller should reject the login with
// a locked-out response *before* looking up the password so timing does
// not leak the lockout state to users who are not yet throttled.
func (t *loginThrottle) Allow(username string) bool {
	if username == "" {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	w, ok := t.failures[username]
	if !ok {
		return true
	}
	now := t.nowClock()
	if !w.lockedUntil.IsZero() && now.Before(w.lockedUntil) {
		return false
	}
	// If the lockout has expired the account gets a clean slate on the
	// very next attempt — no half-decayed history.
	if !w.lockedUntil.IsZero() && !now.Before(w.lockedUntil) {
		delete(t.failures, username)
	}
	return true
}

// RecordFailure increments the fail counter for username. When the counter
// hits the configured maximum inside the sliding window the account is
// locked out for the configured duration.
func (t *loginThrottle) RecordFailure(username string) {
	if username == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.nowClock()
	w := t.failures[username]
	if w == nil {
		w = &failWindow{}
		t.failures[username] = w
	}
	// Drop stale stamps outside the sliding window.
	cutoff := now.Add(-t.window)
	trimmed := w.stamps[:0]
	for _, s := range w.stamps {
		if s.After(cutoff) {
			trimmed = append(trimmed, s)
		}
	}
	w.stamps = append(trimmed, now)
	if len(w.stamps) >= t.max {
		w.lockedUntil = now.Add(t.lockout)
	}
}

// Clear wipes the failure record for username after a successful login,
// so a good password immediately erases any pending lockout risk.
func (t *loginThrottle) Clear(username string) {
	if username == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, username)
}
