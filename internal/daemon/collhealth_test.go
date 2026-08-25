package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// Regression tests for issue #456: a collector that cannot read its source
// must surface in status as collectors_state DEGRADED instead of the daemon
// reporting only enforcement health while observing nothing (#454 field case).

func TestCollectorsState_NoneWithoutCollectors(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	state, detail := d.collectorsState()
	if state != CollNone {
		t.Fatalf("state = %q, want NONE", state)
	}
	if !strings.Contains(detail, "no collectors configured") {
		t.Errorf("detail = %q, want the nothing-observed explanation", detail)
	}
}

func TestCollectorsState_DegradesAtAlertThresholdAndRecovers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := &Daemon{
		collFailureAlert: 3,
		collectors:       []sdk.Collector{&scriptedCollector{}},
	}
	err := errors.New("journald: journalctl exited: exit status 1: insufficient permissions")

	// Below the threshold the aggregate stays OK — transient failures
	// (log rotation, journald restart) must not flap the status banner.
	d.recordCollectorFailure(ctx, "journald:ssh", 1, err)
	d.recordCollectorFailure(ctx, "journald:ssh", 2, err)
	if state, _ := d.collectorsState(); state != CollOK {
		t.Fatalf("state = %q before the threshold, want OK", state)
	}

	// The threshold failure flips DEGRADED, naming collector, streak, error.
	d.recordCollectorFailure(ctx, "journald:ssh", 3, err)
	state, detail := d.collectorsState()
	if state != CollDegraded {
		t.Fatalf("state = %q at the threshold, want DEGRADED", state)
	}
	for _, want := range []string{"journald:ssh", "3 consecutive failures", "insufficient permissions"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail = %q, missing %q", detail, want)
		}
	}

	// A stable run resets the streak and clears the degraded state.
	d.recordCollectorHealthy(ctx, "journald:ssh")
	if state, detail := d.collectorsState(); state != CollOK || detail != "" {
		t.Fatalf("state = %q (%q) after recovery, want OK with empty detail", state, detail)
	}
}

func TestCollectorsState_ListsOnlyDegradedCollectorsSorted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := &Daemon{
		collFailureAlert: 2,
		collectors:       []sdk.Collector{&scriptedCollector{}, &scriptedCollector{}},
	}
	d.recordCollectorFailure(ctx, "journald:ssh", 2, errors.New("boom-ssh"))
	d.recordCollectorFailure(ctx, "file:/var/log/nginx/access.log", 2, errors.New("boom-nginx"))
	// journald:caddy stays healthy: one failure, below the alert threshold.
	d.recordCollectorFailure(ctx, "journald:caddy", 1, errors.New("transient"))

	state, detail := d.collectorsState()
	if state != CollDegraded {
		t.Fatalf("state = %q, want DEGRADED", state)
	}
	if strings.Contains(detail, "journald:caddy") {
		t.Errorf("detail %q lists a non-degraded collector", detail)
	}
	// Sorted output: file:… before journald:… — deterministic for tests and
	// for operators diffing status over time.
	if strings.Index(detail, "file:/var/log/nginx/access.log") > strings.Index(detail, "journald:ssh") {
		t.Errorf("detail %q is not sorted by collector name", detail)
	}
}

// TestRunCollector_FeedsCollectorHealth wires the real supervisor to a
// collector that always fails and asserts the health registry (and thus
// status) flips DEGRADED — the end-to-end path of issue #456.
func TestRunCollector_FeedsCollectorHealth(t *testing.T) {
	t.Parallel()
	sc := &scriptedCollector{
		runFn: func(int, context.Context, chan<- sdk.RawLine) error {
			return errors.New("journalctl exited: insufficient permissions")
		},
	}
	d := &Daemon{
		collBackoffBase:   time.Millisecond,
		collBackoffMax:    2 * time.Millisecond,
		collStableRuntime: time.Hour, // failures are all short-lived
		collFailureAlert:  2,
		collectors:        []sdk.Collector{sc},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		d.runCollector(ctx, sc, nil)
		close(done)
	}()

	deadline := time.After(3 * time.Second)
	for {
		state, detail := d.collectorsState()
		if state == CollDegraded {
			if !strings.Contains(detail, "scripted-collector") {
				t.Errorf("detail = %q, want the collector name", detail)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("collectors state never became DEGRADED")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runCollector did not stop after cancellation")
	}
}
