// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Tests for the periodic hardening self-check (issue #563): transition
// semantics (degrade notifies once, steady state silent, recovery
// notifies), N/A-as-healthy, opt-out resolution, and the audit trail.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/internal/unitcheck"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// selfCheckFixtures swaps unitcheck's systemctl reader for fixture output.
// current is guarded so the test can flip fixtures between passes.
type selfCheckFixtures struct {
	mu      sync.Mutex
	systemd bool
	show    map[string]string
}

func (f *selfCheckFixtures) set(show map[string]string, systemd bool) {
	f.mu.Lock()
	f.show, f.systemd = show, systemd
	f.mu.Unlock()
}

func installSelfCheckFixtures(t *testing.T) *selfCheckFixtures {
	t.Helper()
	f := &selfCheckFixtures{systemd: true}
	orig := unitcheck.ShowUnitProps
	unitcheck.ShowUnitProps = func(_ context.Context, unit string) (map[string]string, bool, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if !f.systemd {
			return nil, false, nil
		}
		props := map[string]string{}
		for _, line := range strings.Split(f.show[unit], "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
				props[k] = v
			}
		}
		return props, true, nil
	}
	t.Cleanup(func() { unitcheck.ShowUnitProps = orig })
	return f
}

var (
	selfCheckHardened = map[string]string{
		unitcheck.EnforcerUnitName: "LoadState=loaded\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\nRuntimeDirectory=ezyshield-enforcer",
		unitcheck.DaemonUnitName:   "LoadState=loaded\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRuntimeDirectory=ezyshield",
	}
	selfCheckStripped = map[string]string{
		unitcheck.EnforcerUnitName: "LoadState=loaded\nRestrictAddressFamilies=AF_UNIX\nRuntimeDirectory=ezyshield-enforcer",
		unitcheck.DaemonUnitName:   selfCheckHardened[unitcheck.DaemonUnitName],
	}
)

func newSelfCheckDaemon(t *testing.T) (*Daemon, *fakeNotifier, *store.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	notif := &fakeNotifier{}
	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            false,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:    db,
		Notifier: notify.New([]sdk.Notifier{notif}, 100, time.Hour, nil),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, notif, db
}

func notificationsBySeverity(n *fakeNotifier) map[string]int {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[string]int{}
	for _, m := range n.msgs {
		out[m.Severity]++
	}
	return out
}

func selfCheckAuditOps(t *testing.T, db *store.DB) map[string]int {
	t.Helper()
	entries, err := db.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	out := map[string]int{}
	for _, e := range entries {
		out[e.Op]++
	}
	return out
}

// TestSelfCheck_TransitionSemantics is the core contract: notify ONCE on
// degrade, silence on steady state, notify ONCE on recovery — both
// transitions audited.
func TestSelfCheck_TransitionSemantics(t *testing.T) {
	fx := installSelfCheckFixtures(t)
	d, notif, db := newSelfCheckDaemon(t)
	ctx := context.Background()

	// Healthy pass: silence.
	fx.set(selfCheckHardened, true)
	d.selfCheckPass(ctx)
	if got := notif.Count(); got != 0 {
		t.Fatalf("healthy pass notified %d time(s)", got)
	}

	// Degrade: exactly one CRITICAL + one audit entry.
	fx.set(selfCheckStripped, true)
	d.selfCheckPass(ctx)
	d.selfCheckPass(ctx) // steady degraded state: no second notification
	sev := notificationsBySeverity(notif)
	if sev["critical"] != 1 {
		t.Fatalf("degrade must notify exactly once, got %+v", sev)
	}
	if ops := selfCheckAuditOps(t, db); ops["selfcheck_degraded"] != 1 {
		t.Fatalf("degrade must audit exactly once, got %+v", ops)
	}

	// Recover: exactly one INFO + one audit entry.
	fx.set(selfCheckHardened, true)
	d.selfCheckPass(ctx)
	d.selfCheckPass(ctx) // steady healthy state again: silence
	sev = notificationsBySeverity(notif)
	if sev["info"] != 1 || sev["critical"] != 1 {
		t.Fatalf("recovery must notify exactly once, got %+v", sev)
	}
	ops := selfCheckAuditOps(t, db)
	if ops["selfcheck_recovered"] != 1 {
		t.Fatalf("recovery must audit exactly once, got %+v", ops)
	}

	// The critical notification names the failing check and points at doctor.
	notif.mu.Lock()
	var critical string
	for _, m := range notif.msgs {
		if m.Severity == "critical" {
			critical = m.Body
		}
	}
	notif.mu.Unlock()
	if !strings.Contains(critical, "AF_NETLINK") || !strings.Contains(critical, "doctor") {
		t.Errorf("critical notification lacks the failure/fix pointers: %q", critical)
	}
}

// TestSelfCheck_NAIsHealthy: no systemd (or units absent) must never
// degrade — script/manual installs stay quiet.
func TestSelfCheck_NAIsHealthy(t *testing.T) {
	fx := installSelfCheckFixtures(t)
	d, notif, _ := newSelfCheckDaemon(t)
	fx.set(nil, false) // non-systemd host
	d.selfCheckPass(context.Background())
	if notif.Count() != 0 {
		t.Fatalf("N/A results must count as healthy, got %d notifications", notif.Count())
	}
	if !d.selfCheckHealthy.Load() {
		t.Fatalf("N/A must not flip the health state")
	}
}

// TestSelfCheck_OptOutResolution pins the tri-state config contract.
func TestSelfCheck_OptOutResolution(t *testing.T) {
	t.Parallel()
	on := true
	off := false
	cases := []struct {
		cfg  *config.SelfCheckCfg
		want bool
	}{
		{nil, true},                                  // section absent → on
		{&config.SelfCheckCfg{}, true},               // field omitted → on
		{&config.SelfCheckCfg{Enabled: &on}, true},   // explicit on
		{&config.SelfCheckCfg{Enabled: &off}, false}, // documented opt-out
	}
	for i, tc := range cases {
		c := &config.Config{SelfCheck: tc.cfg}
		if got := c.SelfCheckEnabled(); got != tc.want {
			t.Errorf("case %d: SelfCheckEnabled = %v, want %v", i, got, tc.want)
		}
	}
}

// TestSelfCheck_LoopHonorsCtxAndInterval: the goroutine runs a first pass
// after the initial delay and stops on cancel.
func TestSelfCheck_LoopHonorsCtxAndInterval(t *testing.T) {
	fx := installSelfCheckFixtures(t)
	d, notif, _ := newSelfCheckDaemon(t)
	fx.set(selfCheckStripped, true)
	d.selfCheckInitial = 10 * time.Millisecond
	d.selfCheckInterval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	go d.runSelfCheck(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for notif.Count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if notif.Count() == 0 {
		t.Fatalf("loop never ran a pass")
	}
}

// TestSelfCheck_ProbeSkippedWithoutNFTables: with no nftables enforcer
// configured the netlink probe never runs (only the 3 unit checks do), so
// a hardened fixture stays healthy without any enforcer socket.
func TestSelfCheck_ProbeSkippedWithoutNFTables(t *testing.T) {
	fx := installSelfCheckFixtures(t)
	d, notif, _ := newSelfCheckDaemon(t)
	if d.selfCheckEnfSocket != "" {
		t.Fatalf("no nftables config: probe socket must be empty, got %q", d.selfCheckEnfSocket)
	}
	fx.set(selfCheckHardened, true)
	d.selfCheckPass(context.Background())
	if notif.Count() != 0 {
		t.Fatalf("hardened units without enforcer must stay healthy")
	}
}
