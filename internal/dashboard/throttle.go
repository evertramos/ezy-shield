// SPDX-License-Identifier: AGPL-3.0-only

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

	// throttleGlobalMax caps total failed attempts across ALL usernames in a
	// throttleWindow. The per-username throttle never trips for an attacker
	// who sends a fresh username every request, so without a global ceiling
	// they could grow the failures map and burn a ~300 ms decoy PBKDF2 per
	// request indefinitely (issue #360). When the global budget is exhausted
	// every login is rejected before the password lookup until the window
	// drains — a self-healing brute-force circuit breaker. The bound sits
	// well above throttleMaxFailures so a handful of honest fat-finger
	// lockouts never trip it.
	throttleGlobalMax = 100
)

type loginThrottle struct {
	max       int
	window    time.Duration
	lockout   time.Duration
	globalMax int
	nowClock  func() time.Time

	mu           sync.Mutex
	failures     map[string]*failWindow
	globalStamps []time.Time
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
		max:       throttleMaxFailures,
		window:    throttleWindow,
		lockout:   throttleLockout,
		globalMax: throttleGlobalMax,
		nowClock:  time.Now,
		failures:  make(map[string]*failWindow),
	}
}

// trimStamps drops timestamps at or before cutoff, reusing the backing array.
func trimStamps(stamps []time.Time, cutoff time.Time) []time.Time {
	trimmed := stamps[:0]
	for _, s := range stamps {
		if s.After(cutoff) {
			trimmed = append(trimmed, s)
		}
	}
	return trimmed
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
	now := t.nowClock()

	// Global circuit breaker first: if the whole login surface is over budget
	// for this window, reject before any per-account work so an attacker
	// cycling usernames can't keep burning PBKDF2 (issue #360).
	t.globalStamps = trimStamps(t.globalStamps, now.Add(-t.window))
	if len(t.globalStamps) >= t.globalMax {
		return false
	}

	w, ok := t.failures[username]
	if !ok {
		return true
	}
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
	cutoff := now.Add(-t.window)

	// Record against the global window (bounded brute-force circuit breaker).
	t.globalStamps = append(trimStamps(t.globalStamps, cutoff), now)

	w := t.failures[username]
	if w == nil {
		w = &failWindow{}
		t.failures[username] = w
	}
	w.stamps = append(trimStamps(w.stamps, cutoff), now)
	if len(w.stamps) >= t.max {
		w.lockedUntil = now.Add(t.lockout)
	}

	// Keep the map bounded: an attacker cycling usernames creates one entry
	// each, and expired entries would otherwise linger until that exact
	// username is retried. Prune opportunistically once the map is larger
	// than the global budget could justify.
	if len(t.failures) > t.globalMax {
		t.pruneLocked(now)
	}
}

// pruneLocked drops entries with no in-window failures and no active lockout.
// Caller must hold t.mu.
func (t *loginThrottle) pruneLocked(now time.Time) {
	cutoff := now.Add(-t.window)
	for name, w := range t.failures {
		w.stamps = trimStamps(w.stamps, cutoff)
		locked := !w.lockedUntil.IsZero() && now.Before(w.lockedUntil)
		if len(w.stamps) == 0 && !locked {
			delete(t.failures, name)
		}
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
