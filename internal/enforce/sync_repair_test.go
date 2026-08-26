package enforce_test

// Tests for the reconcile repair reporting (issue #214): Sync counts what it
// had to re-add/remove to converge store and kernel, distinguishes the boot
// reconcile (expected restart recovery) from real drift, and the Gate /
// MultiEnforcer wrappers forward the facet so the daemon can audit repairs.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func repairTargets(ips ...string) []sdk.Target {
	out := make([]sdk.Target, 0, len(ips))
	for _, ip := range ips {
		out = append(out, sdk.Target{IP: netip.MustParseAddr(ip), TTL: time.Hour})
	}
	return out
}

func TestSync_RepairCountsAndBootFlag(t *testing.T) {
	t.Parallel()
	ms := newMockHelper(t)
	e := enforce.New(ms.sock, nil)
	ctx := context.Background()

	// Boot reconcile: kernel empty, store has two bans — everything is
	// re-added, and the firstSync flag marks it as expected recovery.
	ms.setListIPs(nil)
	if err := e.Sync(ctx, repairTargets("192.0.2.10", "192.0.2.11")); err != nil {
		t.Fatalf("boot Sync: %v", err)
	}
	added, removed, first := e.LastSyncRepairs()
	if added != 2 || removed != 0 || !first {
		t.Fatalf("boot repairs = (%d, %d, first=%v), want (2, 0, true)", added, removed, first)
	}

	// Post-boot drift: one wanted element vanished from the kernel
	// (mid-write interruption) and one orphan appeared. Both directions
	// must be counted, and firstSync must now be false.
	ms.setListIPs([]string{"192.0.2.11", "198.51.100.99"})
	if err := e.Sync(ctx, repairTargets("192.0.2.10", "192.0.2.11")); err != nil {
		t.Fatalf("drift Sync: %v", err)
	}
	added, removed, first = e.LastSyncRepairs()
	if added != 1 || removed != 1 || first {
		t.Fatalf("drift repairs = (%d, %d, first=%v), want (1, 1, false)", added, removed, first)
	}

	// Converged: no repairs.
	ms.setListIPs([]string{"192.0.2.10", "192.0.2.11"})
	if err := e.Sync(ctx, repairTargets("192.0.2.10", "192.0.2.11")); err != nil {
		t.Fatalf("converged Sync: %v", err)
	}
	if added, removed, _ := e.LastSyncRepairs(); added != 0 || removed != 0 {
		t.Fatalf("converged repairs = (%d, %d), want (0, 0)", added, removed)
	}
}

func TestSyncRepairs_ForwardedThroughGateAndMulti(t *testing.T) {
	t.Parallel()
	ms := newMockHelper(t)
	e := enforce.New(ms.sock, nil)
	wrapped := enforce.NewGate(enforce.NewMulti(e), nil, nil)
	ctx := context.Background()

	ms.setListIPs(nil)
	if err := wrapped.Sync(ctx, repairTargets("192.0.2.20")); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	ms.setListIPs(nil) // element vanished again → drift on the second pass
	if err := wrapped.Sync(ctx, repairTargets("192.0.2.20")); err != nil {
		t.Fatalf("Sync 2: %v", err)
	}

	var rep enforce.SyncRepairReporter = wrapped
	added, removed, first := rep.LastSyncRepairs()
	if added != 1 || removed != 0 || first {
		t.Fatalf("forwarded repairs = (%d, %d, first=%v), want (1, 0, false)", added, removed, first)
	}
}
