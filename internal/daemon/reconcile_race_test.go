// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Tests for the reconcile TOCTOU (issue #575): syncEnforcer snapshots the
// desired state (store.ActiveBans) BEFORE the enforcer reads the kernel
// state, so a ban that commits inside that window is in the kernel but not
// in `want` — and the reconcile deletes the ban it just applied, leaving the
// attacker unblocked until the next cycle re-adds it.
//
// The fix serialises every store+kernel ban/unban mutation against the
// reconcile with d.enforceMu. These tests pin that invariant behaviourally:
// while a Sync is in flight, no ban/unban path may touch the enforcer or the
// store; the mutation must land entirely after the reconcile finishes.

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// raceProbeWindow is how long a test waits for a mutation to sneak into the
// Sync window before concluding it is correctly blocked. Generous enough to
// be reliable on a loaded CI runner, short enough to keep the suite fast.
const raceProbeWindow = 500 * time.Millisecond

// raceTestTimeout bounds every channel wait so a regression fails the test
// instead of hanging the suite.
const raceTestTimeout = 10 * time.Second

// gatedEnforcer is an sdk.Enforcer whose Sync blocks until released,
// simulating the slow listIPs RPC the real nftables enforcer performs. Every
// call is appended to an ordered log so the test can assert that a ban or
// unban never straddles a Sync.
type gatedEnforcer struct {
	mu   sync.Mutex
	log  []string
	bans []sdk.Target

	entered chan struct{} // closed-ish: one token per Sync entry
	release chan struct{} // test closes this to let Sync return
}

func newGatedEnforcer() *gatedEnforcer {
	return &gatedEnforcer{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
}

func (g *gatedEnforcer) record(entry string) {
	g.mu.Lock()
	g.log = append(g.log, entry)
	g.mu.Unlock()
}

func (g *gatedEnforcer) calls() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, len(g.log))
	copy(out, g.log)
	return out
}

func (g *gatedEnforcer) Name() string { return "gated" }

func (g *gatedEnforcer) Ban(_ context.Context, t sdk.Target) error {
	g.mu.Lock()
	g.log = append(g.log, "ban")
	g.bans = append(g.bans, t)
	g.mu.Unlock()
	return nil
}

func (g *gatedEnforcer) Unban(_ context.Context, _ sdk.Target) error {
	g.record("unban")
	return nil
}

func (g *gatedEnforcer) Sync(ctx context.Context, _ []sdk.Target) error {
	g.record("sync-start")
	select {
	case g.entered <- struct{}{}:
	default:
	}
	select {
	case <-g.release:
	case <-ctx.Done():
	case <-time.After(raceTestTimeout):
	}
	g.record("sync-end")
	return nil
}

var _ sdk.Enforcer = (*gatedEnforcer)(nil)

// newRaceDaemon builds an armed daemon over a real in-memory store and the
// gated enforcer.
func newRaceDaemon(t *testing.T) (*Daemon, *store.DB, *gatedEnforcer) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	enf := newGatedEnforcer()
	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            true,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:      db,
		Enforcer:   enf,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, db, enf
}

// startBlockedSync runs syncEnforcer in a goroutine and returns once the
// enforcer's Sync has entered (and is blocked). The returned func releases
// Sync and waits for the reconcile goroutine to finish.
func startBlockedSync(t *testing.T, d *Daemon, enf *gatedEnforcer) (finish func()) {
	t.Helper()
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- d.syncEnforcer(ctx) }()

	select {
	case <-enf.entered:
	case <-time.After(raceTestTimeout):
		t.Fatal("Sync never started — the reconcile goroutine is wedged")
	}

	var once sync.Once
	return func() {
		once.Do(func() { close(enf.release) })
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("syncEnforcer: %v", err)
			}
		case <-time.After(raceTestTimeout):
			t.Fatal("syncEnforcer never returned after release")
		}
	}
}

// assertNotBeforeRelease waits raceProbeWindow for done to fire. Firing means
// the mutation completed while the reconcile still held the enforcer — the
// exact TOCTOU of issue #575.
func assertNotBeforeRelease(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
		t.Fatalf("%s completed while a reconcile was in flight — "+
			"the mutation is not serialised against Sync (issue #575)", what)
	case <-time.After(raceProbeWindow):
	}
}

func waitDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(raceTestTimeout):
		t.Fatalf("%s never completed after the reconcile finished", what)
	}
}

// assertOrder requires the recorded enforcer calls to be exactly want.
func assertOrder(t *testing.T, enf *gatedEnforcer, want ...string) {
	t.Helper()
	got := enf.calls()
	if len(got) != len(want) {
		t.Fatalf("enforcer calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("enforcer calls = %v, want %v", got, want)
		}
	}
}

// TestDispatchBan_WaitsForInFlightReconcile is the pipeline half of the race:
// the decision engine has already written the store row, dispatch applies the
// kernel rule. If that kernel write lands inside a reconcile whose desired
// state was snapshotted earlier, Sync deletes it as stale.
func TestDispatchBan_WaitsForInFlightReconcile(t *testing.T) {
	d, _, enf := newRaceDaemon(t)
	ctx := context.Background()

	finish := startBlockedSync(t, d, enf)

	banDone := make(chan struct{})
	go func() {
		defer close(banDone)
		d.dispatch(ctx, sdk.Action{
			Op:     "ban",
			IP:     netip.MustParseAddr("192.0.2.10"),
			TTL:    time.Hour,
			Strike: 1,
			Reason: "test",
		})
	}()

	assertNotBeforeRelease(t, banDone, "pipeline ban")
	finish()
	waitDone(t, banDone, "pipeline ban")

	assertOrder(t, enf, "sync-start", "sync-end", "ban")
}

// TestHandleBan_WaitsForInFlightReconcile is the manual-ban half. handleBan
// writes the kernel FIRST and the store row second, so a reconcile straddling
// it sees the kernel element without the desired-state row.
func TestHandleBan_WaitsForInFlightReconcile(t *testing.T) {
	d, db, enf := newRaceDaemon(t)
	ctx := context.Background()
	target := netip.MustParseAddr("198.51.100.23")

	finish := startBlockedSync(t, d, enf)

	banDone := make(chan struct{})
	var resp SocketResponse
	go func() {
		defer close(banDone)
		resp = d.handleBan(ctx, SocketRequest{Verb: "ban", IP: target.String(), TTL: "1h"})
	}()

	assertNotBeforeRelease(t, banDone, "manual ban")

	// Neither side of the mutation may be visible yet: the store row must not
	// have landed while the reconcile still holds its desired-state snapshot.
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	for _, b := range bans {
		if b.IP == target {
			t.Fatalf("manual ban row for %s landed mid-reconcile — "+
				"store and kernel writes are not atomic w.r.t. Sync (issue #575)", target)
		}
	}

	finish()
	waitDone(t, banDone, "manual ban")

	if resp.Error != "" {
		t.Fatalf("handleBan: %s", resp.Error)
	}
	assertOrder(t, enf, "sync-start", "sync-end", "ban")

	bans, err = db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans after: %v", err)
	}
	found := false
	for _, b := range bans {
		if b.IP == target {
			found = true
		}
	}
	if !found {
		t.Fatalf("manual ban for %s never reached bans_active", target)
	}
}

// TestHandleUnban_WaitsForInFlightReconcile is the inverse race: handleUnban
// removes the kernel element first and the store row second, so a reconcile
// straddling it re-adds the ban the operator just lifted.
func TestHandleUnban_WaitsForInFlightReconcile(t *testing.T) {
	d, db, enf := newRaceDaemon(t)
	ctx := context.Background()
	target := netip.MustParseAddr("203.0.113.44")

	if err := db.RecordStrike(ctx, sdk.Action{
		IP: target, Op: "ban", TTL: time.Hour, Strike: 1, Reason: "seed",
	}); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}

	finish := startBlockedSync(t, d, enf)

	unbanDone := make(chan struct{})
	var resp SocketResponse
	go func() {
		defer close(unbanDone)
		resp = d.handleUnban(ctx, SocketRequest{Verb: "unban", IP: target.String()})
	}()

	assertNotBeforeRelease(t, unbanDone, "manual unban")

	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	still := false
	for _, b := range bans {
		if b.IP == target {
			still = true
		}
	}
	if !still {
		t.Fatalf("unban row for %s was deleted mid-reconcile — "+
			"store and kernel writes are not atomic w.r.t. Sync (issue #575)", target)
	}

	finish()
	waitDone(t, unbanDone, "manual unban")

	if resp.Error != "" {
		t.Fatalf("handleUnban: %s", resp.Error)
	}
	assertOrder(t, enf, "sync-start", "sync-end", "unban")
}
