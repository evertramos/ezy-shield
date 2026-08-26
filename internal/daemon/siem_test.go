// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Tests for the SIEM audit tail (issue #203).

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/siem"
)

type siemCapture struct {
	mu     sync.Mutex
	events []siem.Event
}

func (c *siemCapture) emit(e siem.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *siemCapture) actions() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.events))
	for _, e := range c.events {
		out = append(out, e.Action)
	}
	return out
}

// TestRunSIEMTail_ForwardsAuditedActions pins the choke-point property:
// rows written to the audit log surface as SIEM events, plus the lifecycle
// start/stop events, and pre-existing history is NOT replayed.
func TestRunSIEMTail_ForwardsAuditedActions(t *testing.T) {
	d := newTestDaemonForSocket(t, false)
	cap := &siemCapture{}
	d.siemEmit = cap.emit
	d.siemTailTick = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())

	// History from before this run must not be replayed.
	if err := d.store.AuditSystem(ctx, "old_event", "from a previous run"); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		d.runSIEMTail(ctx)
		close(done)
	}()
	// The baseline is captured before daemon_start is emitted — wait for it
	// so the writes below are unambiguously "new" rows.
	startDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(startDeadline) && !contains(cap.actions(), "daemon_start") {
		time.Sleep(5 * time.Millisecond)
	}

	// New audited actions after start.
	if err := d.store.AuditSystem(ctx, "arm", "manual arm"); err != nil {
		t.Fatal(err)
	}
	if err := d.store.AuditOp(ctx, "ban",
		netip.PrefixFrom(netip.MustParseAddr("192.0.2.9"), 32), time.Hour, "test ban"); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		acts := cap.actions()
		if contains(acts, "arm") && contains(acts, "ban") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	acts := cap.actions()
	if len(acts) == 0 || acts[0] != "daemon_start" {
		t.Fatalf("first event = %v, want daemon_start", acts)
	}
	if acts[len(acts)-1] != "daemon_stop" {
		t.Fatalf("last event = %v, want daemon_stop", acts)
	}
	if contains(acts, "old_event") {
		t.Fatalf("pre-existing history replayed: %v", acts)
	}
	if !contains(acts, "arm") || !contains(acts, "ban") {
		t.Fatalf("audited actions missing: %v", acts)
	}
	// The ban event carries the audit row's substance.
	for _, e := range cap.events {
		if e.Action == "ban" {
			if e.IP.String() != "192.0.2.9" || e.TTL != time.Hour || e.Rule == "" {
				t.Errorf("ban event fields = %+v", e)
			}
		}
	}
}

func TestRunSIEMTail_NoEmitterIsDisabled(t *testing.T) {
	d := newTestDaemonForSocket(t, false)
	d.runSIEMTail(context.Background()) // must return immediately
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
