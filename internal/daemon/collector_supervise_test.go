// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// scriptedCollector is a fake sdk.Collector whose per-attempt behavior is driven
// by runFn. It records how many times Run was entered so tests can assert
// restart (or the absence of one). No real log source is touched.
type scriptedCollector struct {
	runFn func(attempt int, ctx context.Context, out chan<- sdk.RawLine) error

	mu       sync.Mutex
	attempts int
}

func (s *scriptedCollector) Run(ctx context.Context, out chan<- sdk.RawLine) error {
	s.mu.Lock()
	s.attempts++
	n := s.attempts
	s.mu.Unlock()
	return s.runFn(n, ctx, out)
}

func (s *scriptedCollector) Attempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

// Name gives the supervisor a stable identity for logs/alerts.
func (s *scriptedCollector) Name() string { return "scripted-collector" }

// recordingNotifier captures every Notification it is asked to send.
type recordingNotifier struct {
	mu   sync.Mutex
	msgs []sdk.Notification
}

func (r *recordingNotifier) Name() string { return "recording" }

func (r *recordingNotifier) Send(_ context.Context, msg sdk.Notification) error {
	r.mu.Lock()
	r.msgs = append(r.msgs, msg)
	r.mu.Unlock()
	return nil
}

func (r *recordingNotifier) all() []sdk.Notification {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]sdk.Notification, len(r.msgs))
	copy(out, r.msgs)
	return out
}

// TestRunCollector_RestartsAfterErrorAndResumes proves the core fix (issue #305):
// a collector that returns a runtime error on its first Run is restarted and
// resumes delivering events, instead of silently dying until daemon restart.
func TestRunCollector_RestartsAfterErrorAndResumes(t *testing.T) {
	t.Parallel()

	d := &Daemon{
		collBackoffBase:   time.Millisecond,
		collBackoffMax:    5 * time.Millisecond,
		collStableRuntime: time.Hour, // never auto-reset during the test
	}
	out := make(chan sdk.RawLine, 1)

	sc := &scriptedCollector{
		runFn: func(attempt int, ctx context.Context, o chan<- sdk.RawLine) error {
			if attempt == 1 {
				// Mimic filetail's "reopen after rotation" fatal return.
				return errors.New("filetail: reopen after rotation: boom")
			}
			// Second run: deliver an event, then block until shutdown.
			select {
			case o <- sdk.RawLine{Source: "file:/var/log/test", Line: []byte("hit from 192.0.2.10")}:
			case <-ctx.Done():
				return ctx.Err()
			}
			<-ctx.Done()
			return ctx.Err()
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		d.runCollector(ctx, sc, out)
		close(done)
	}()

	select {
	case rl := <-out:
		if !strings.Contains(string(rl.Line), "192.0.2.10") {
			t.Fatalf("unexpected line after restart: %q", rl.Line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("collector was not restarted: no event delivered after first-run error")
	}

	if got := sc.Attempts(); got < 2 {
		t.Fatalf("expected the collector to be re-run, attempts=%d", got)
	}

	// Clean shutdown must unwind the supervisor.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCollector did not return after context cancellation")
	}
}

// TestRunCollector_CtxCancelDoesNotRestart proves clean shutdown is preserved:
// when the context is cancelled the collector is NOT restarted, even though its
// Run returns a (cancellation) error. Distinguishing ctx-cancel from a genuine
// runtime error is the safety property that keeps SIGTERM drain from hot-looping.
func TestRunCollector_CtxCancelDoesNotRestart(t *testing.T) {
	t.Parallel()

	d := &Daemon{collBackoffBase: time.Millisecond}

	sc := &scriptedCollector{
		runFn: func(_ int, ctx context.Context, _ chan<- sdk.RawLine) error {
			<-ctx.Done()
			return ctx.Err() // non-nil, but caused by cancellation
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		d.runCollector(ctx, sc, nil)
		close(done)
	}()

	// Let the collector enter Run, then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCollector did not stop after cancellation")
	}

	// Give any (buggy) restart a chance to increment the counter.
	time.Sleep(50 * time.Millisecond)
	if got := sc.Attempts(); got != 1 {
		t.Fatalf("ctx cancellation must not restart the collector; attempts=%d", got)
	}
}

// TestRunCollector_CleanNilExitDoesNotRestart proves a collector that finishes
// its source on its own (returns nil without cancellation) is not hot-looped.
func TestRunCollector_CleanNilExitDoesNotRestart(t *testing.T) {
	t.Parallel()

	d := &Daemon{collBackoffBase: time.Millisecond}

	sc := &scriptedCollector{
		runFn: func(_ int, _ context.Context, _ chan<- sdk.RawLine) error {
			return nil // source completed
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		d.runCollector(ctx, sc, nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCollector should return on a clean nil exit")
	}

	time.Sleep(50 * time.Millisecond)
	if got := sc.Attempts(); got != 1 {
		t.Fatalf("clean nil exit must not restart; attempts=%d", got)
	}
}

// TestRunCollector_BackoffIsBounded proves the restart delay grows but is capped
// (no busy loop, no unbounded wait), and that cancellation still breaks the loop.
func TestRunCollector_BackoffIsBounded(t *testing.T) {
	t.Parallel()

	const (
		base = 5 * time.Millisecond
		mx   = 20 * time.Millisecond
	)
	d := &Daemon{
		collBackoffBase:   base,
		collBackoffMax:    mx,
		collStableRuntime: time.Hour,
	}

	var mu sync.Mutex
	var times []time.Time
	sc := &scriptedCollector{
		runFn: func(_ int, _ context.Context, _ chan<- sdk.RawLine) error {
			mu.Lock()
			times = append(times, time.Now())
			mu.Unlock()
			return errors.New("always fails")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// Blocks until the context deadline; if the loop ignored cancellation this
	// would hang and the test would time out.
	d.runCollector(ctx, sc, nil)

	mu.Lock()
	defer mu.Unlock()

	if len(times) < 3 {
		t.Fatalf("expected several restart attempts, got %d", len(times))
	}
	// Busy-loop guard: base 5ms capped at 20ms over 300ms is far fewer than this.
	if len(times) > 80 {
		t.Fatalf("possible busy loop: %d attempts in 300ms", len(times))
	}

	slack := 50 * time.Millisecond
	var maxGap time.Duration
	for i := 1; i < len(times); i++ {
		gap := times[i].Sub(times[i-1])
		if gap > mx+slack {
			t.Fatalf("restart interval %v exceeds cap %v (+slack)", gap, mx)
		}
		if gap > maxGap {
			maxGap = gap
		}
	}
	// Escalation actually happened (a later delay grew beyond the base).
	if maxGap < 2*base {
		t.Fatalf("backoff did not escalate: max interval %v", maxGap)
	}
}

// TestRunCollector_PanicIsRecoveredAndRestarted proves a panic in one Run is
// converted to a restartable error rather than killing the supervisor goroutine.
func TestRunCollector_PanicIsRecoveredAndRestarted(t *testing.T) {
	t.Parallel()

	d := &Daemon{
		collBackoffBase:   time.Millisecond,
		collBackoffMax:    5 * time.Millisecond,
		collStableRuntime: time.Hour,
	}
	out := make(chan sdk.RawLine, 1)

	sc := &scriptedCollector{
		runFn: func(attempt int, ctx context.Context, o chan<- sdk.RawLine) error {
			if attempt == 1 {
				panic("collector blew up")
			}
			select {
			case o <- sdk.RawLine{Source: "file:/var/log/test", Line: []byte("recovered 198.51.100.7")}:
			case <-ctx.Done():
				return ctx.Err()
			}
			<-ctx.Done()
			return ctx.Err()
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		d.runCollector(ctx, sc, out)
		close(done)
	}()

	select {
	case rl := <-out:
		if !strings.Contains(string(rl.Line), "198.51.100.7") {
			t.Fatalf("unexpected line after panic restart: %q", rl.Line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("collector was not restarted after a panic")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCollector did not return after cancellation")
	}
}

// TestRunCollectorOnce_PanicAlertNamesTheCollector (issue #438): the panic
// alert's Title must carry the panicking collector's identity — the notifier
// dedups system notifications by severity+Title, so a constant Title made
// panics from different collectors collapse into one suppressed alert and
// hid which collector was panic-looping.
func TestRunCollectorOnce_PanicAlertNamesTheCollector(t *testing.T) {
	t.Parallel()

	rec := &recordingNotifier{}
	disp := notify.New([]sdk.Notifier{rec}, 0, time.Millisecond, nil)
	d := &Daemon{notifier: disp}

	sc := &scriptedCollector{
		runFn: func(_ int, _ context.Context, _ chan<- sdk.RawLine) error {
			panic("collector blew up")
		},
	}

	if err := d.runCollectorOnce(context.Background(), sc, nil); err == nil {
		t.Fatal("recovered panic must surface as an error to the supervisor")
	}

	msgs := rec.all()
	if len(msgs) != 1 {
		t.Fatalf("expected exactly 1 panic alert, got %d", len(msgs))
	}
	m := msgs[0]
	if m.Severity != "critical" {
		t.Fatalf("alert severity = %q, want critical", m.Severity)
	}
	if !strings.Contains(m.Title, "scripted-collector") {
		t.Fatalf("panic alert Title must name the collector (it is the dedup key): %q", m.Title)
	}
	if !strings.Contains(m.Body, "collector blew up") {
		t.Fatalf("panic alert body must carry the panic value: %q", m.Body)
	}
}

// TestRunCollector_AlertsAfterConsecutiveFailures proves a permanently broken
// collector surfaces to the operator via a critical notification rather than
// retrying silently forever.
func TestRunCollector_AlertsAfterConsecutiveFailures(t *testing.T) {
	t.Parallel()

	rec := &recordingNotifier{}
	disp := notify.New([]sdk.Notifier{rec}, 0, time.Millisecond, nil)

	d := &Daemon{
		notifier:          disp,
		collBackoffBase:   time.Millisecond,
		collBackoffMax:    2 * time.Millisecond,
		collStableRuntime: time.Hour,
		collFailureAlert:  3,
	}

	sc := &scriptedCollector{
		runFn: func(_ int, _ context.Context, _ chan<- sdk.RawLine) error {
			return errors.New("permanently broken")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	d.runCollector(ctx, sc, nil)

	msgs := rec.all()
	if len(msgs) == 0 {
		t.Fatal("expected a critical alert after repeated failures, got none")
	}
	m := msgs[0]
	if m.Severity != "critical" {
		t.Fatalf("alert severity = %q, want critical", m.Severity)
	}
	if !strings.Contains(m.Body, "scripted-collector") || !strings.Contains(m.Body, "3 times") {
		t.Fatalf("alert body should name the collector and failure count: %q", m.Body)
	}
	if got := sc.Attempts(); got < 3 {
		t.Fatalf("expected at least the alert threshold of attempts, got %d", got)
	}
}
