// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Regression tests for issue #583: a ban the store already holds that the
// enforce-side gate refuses at dispatch time must be DEFERRED (WARN, no
// critical alert, no DEGRADED) and applied through the same gate once the
// peer is gone — never while it is present; exhaustion is audited; a ban
// lifted meanwhile is dropped. Plus the ADR-0013 wiring: with
// anti_lockout.require_authenticated on, the gate receives the narrowed
// probe.

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// togglePeer is a peer probe the test flips: present → the gate refuses.
type togglePeer struct {
	mu      sync.Mutex
	ip      netip.Addr
	present bool
}

func (p *togglePeer) set(v bool) { p.mu.Lock(); p.present = v; p.mu.Unlock() }
func (p *togglePeer) peers() []netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.present {
		return []netip.Addr{p.ip}
	}
	return nil
}

// newGatedBanDaemon builds an armed daemon whose enforcer is the real
// enforce.Gate over a fakeEnforcer, judged by probe, with a notifier that
// records every message and a fast retry cadence.
func newGatedBanDaemon(t *testing.T, probe func() []netip.Addr) (*Daemon, *store.DB, *fakeEnforcer, *fakeNotifier) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	inner := &fakeEnforcer{}
	notif := &fakeNotifier{}
	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            true,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:           db,
		Enforcer:        enforce.NewGate(inner, nil, probe),
		Notifier:        notify.New([]sdk.Notifier{notif}, 100, 0, nil),
		SocketPath:      "",
		SSHRecheckDelay: 20 * time.Millisecond,
		SSHRecheckTick:  5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, db, inner, notif
}

// storeBan commits the row exactly as Decide does before dispatch.
func storeBan(t *testing.T, db *store.DB, ip netip.Addr, ttl time.Duration) {
	t.Helper()
	if err := db.RecordManualBan(context.Background(), ip, ttl, "test ban", false); err != nil {
		t.Fatalf("RecordManualBan: %v", err)
	}
}

// criticalCount returns how many critical (system) notifications were sent —
// the regular "[ban] <ip> — strike N" message dispatch always emits is not
// one of them.
func criticalCount(n *fakeNotifier) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, m := range n.msgs {
		if m.Severity == "critical" {
			c++
		}
	}
	return c
}

func auditOpsFor(t *testing.T, db *store.DB, ip netip.Addr) []string {
	t.Helper()
	entries, err := db.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	var ops []string
	for _, e := range entries {
		if e.IP == ip.String() {
			ops = append(ops, e.Op)
		}
	}
	return ops
}

// TestGatedBan_DeferredUntilPeerGone is the field scenario: the engine has
// committed the ban, the gate sees the attacker's socket and refuses. The
// ban must reach the inner enforcer — with its remaining TTL — only after
// the socket is gone, with no critical alert and no DEGRADED in between.
func TestGatedBan_DeferredUntilPeerGone(t *testing.T) {
	buf := captureSlogSync(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attacker := netip.MustParseAddr("203.0.113.45")
	peer := &togglePeer{ip: attacker, present: true}
	d, db, inner, notif := newGatedBanDaemon(t, peer.peers)
	storeBan(t, db, attacker, time.Hour)

	d.dispatch(ctx, sdk.Action{IP: attacker, Op: "ban", Strike: 1, TTL: time.Hour, Reason: "test"})

	// Refused at dispatch: nothing enforced, nothing escalated.
	if n := inner.BanCount(); n != 0 {
		t.Fatalf("inner enforcer received %d bans while the peer was present, want 0", n)
	}
	if n := criticalCount(notif); n != 0 {
		t.Fatalf("gate refusal raised %d critical notification(s), want 0 (not an enforcer failure)", n)
	}
	if s, _ := d.enforcementState(); s != EnfActive {
		t.Fatalf("enforcement state = %s after gate refusal, want ACTIVE", s)
	}
	if d.gatedBanRetry.len() != 1 {
		t.Fatalf("deferred enforcement retry not armed (queue len %d)", d.gatedBanRetry.len())
	}
	log := buf.String()
	if !strings.Contains(log, "deferring enforcement") {
		t.Fatalf("no deferral WARN; log:\n%s", log)
	}
	if strings.Contains(log, "enforcer ban failed") {
		t.Fatalf("gate refusal logged as an enforcer failure; log:\n%s", log)
	}

	// Peer still there: the retry loop must keep refusing.
	go d.runSSHRecheck(ctx)
	time.Sleep(120 * time.Millisecond) // several retries
	if n := inner.BanCount(); n != 0 {
		t.Fatalf("retry enforced the ban while the peer was still present (%d bans) — Hard Rule 1 broken", n)
	}

	// Peer gone: the next retry applies the stored ban with its remaining TTL.
	peer.set(false)
	if !waitFor(3*time.Second, func() bool { return inner.BanCount() == 1 }) {
		t.Fatalf("ban never reached the inner enforcer after the peer left; log:\n%s", buf.String())
	}
	inner.mu.Lock()
	got := inner.bans[0]
	inner.mu.Unlock()
	if got.IP != attacker {
		t.Fatalf("enforced %s, want %s", got.IP, attacker)
	}
	if got.TTL <= 0 || got.TTL > time.Hour || got.TTL < 59*time.Minute {
		t.Fatalf("enforced TTL = %s, want the remaining ~1h", got.TTL)
	}
	if !waitFor(time.Second, func() bool { return d.gatedBanRetry.len() == 0 }) {
		t.Fatalf("retry queue not drained after success")
	}
	if n := criticalCount(notif); n != 0 {
		t.Fatalf("deferred success raised %d critical notification(s), want 0", n)
	}
	if s, _ := d.enforcementState(); s != EnfActive {
		t.Fatalf("enforcement state = %s after deferred success, want ACTIVE", s)
	}
	if !strings.Contains(buf.String(), "deferred enforcement applied") {
		t.Errorf("success not logged; log:\n%s", buf.String())
	}
}

// TestGatedBan_ExhaustionIsLoudAndAudited: a peer that never leaves
// outlasts the budget. The ban stays in the store (the reconcile's job),
// the exhaustion is a WARN plus an audit row, and nothing was enforced.
func TestGatedBan_ExhaustionIsLoudAndAudited(t *testing.T) {
	buf := captureSlogSync(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attacker := netip.MustParseAddr("203.0.113.46")
	peer := &togglePeer{ip: attacker, present: true}
	d, db, inner, notif := newGatedBanDaemon(t, peer.peers)
	storeBan(t, db, attacker, time.Hour)

	d.dispatch(ctx, sdk.Action{IP: attacker, Op: "ban", Strike: 1, TTL: time.Hour, Reason: "test"})
	go d.runSSHRecheck(ctx)

	if !waitFor(5*time.Second, func() bool { return d.gatedBanRetry.len() == 0 }) {
		t.Fatalf("retry queue never drained via exhaustion")
	}
	if !waitFor(time.Second, func() bool {
		return strings.Contains(buf.String(), "deferred enforcement retry budget exhausted")
	}) {
		t.Fatalf("no exhaustion WARN; log:\n%s", buf.String())
	}
	if !waitFor(3*time.Second, func() bool {
		for _, op := range auditOpsFor(t, db, attacker) {
			if op == "enforce_deferred_exhausted" {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("no enforce_deferred_exhausted audit row; ops=%v", auditOpsFor(t, db, attacker))
	}
	if n := inner.BanCount(); n != 0 {
		t.Fatalf("exhaustion path enforced %d ban(s), want 0", n)
	}
	if n := criticalCount(notif); n != 0 {
		t.Fatalf("exhaustion raised %d critical notification(s), want 0", n)
	}
	// The row is still the reconcile's to apply.
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range bans {
		if b.IP == attacker && b.Op == "ban" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stored ban vanished during deferral")
	}
}

// TestGatedBan_DroppedWhenBanLifted: an operator unban (or expiry) between
// the refusal and the retry must win — the retry re-reads the store and
// never re-applies a ban the store no longer holds.
func TestGatedBan_DroppedWhenBanLifted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attacker := netip.MustParseAddr("203.0.113.47")
	peer := &togglePeer{ip: attacker, present: true}
	d, db, inner, _ := newGatedBanDaemon(t, peer.peers)
	storeBan(t, db, attacker, time.Hour)

	d.dispatch(ctx, sdk.Action{IP: attacker, Op: "ban", Strike: 1, TTL: time.Hour, Reason: "test"})
	if err := db.Unban(ctx, attacker); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	peer.set(false) // the gate would now let it through — the store must not
	go d.runSSHRecheck(ctx)

	if !waitFor(3*time.Second, func() bool { return d.gatedBanRetry.len() == 0 }) {
		t.Fatalf("retry queue never drained")
	}
	time.Sleep(50 * time.Millisecond) // let the popped retry finish
	if n := inner.BanCount(); n != 0 {
		t.Fatalf("lifted ban was re-applied by the deferred retry (%d bans)", n)
	}
	for _, op := range auditOpsFor(t, db, attacker) {
		if op == "enforce_deferred_exhausted" {
			t.Fatalf("a dropped retry must not be audited as exhaustion")
		}
	}
}

// probeSpyEnforcer records the peer probe the daemon installs (the
// enforce.SSHPeerProbeSetter facet the Gate implements).
type probeSpyEnforcer struct {
	fakeEnforcer
	mu    sync.Mutex
	probe func() []netip.Addr
	calls int
}

func (p *probeSpyEnforcer) SetSSHPeerProbe(fn func() []netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probe = fn
	p.calls++
}

// TestADR0013_GateReceivesNarrowedProbe: with require_authenticated on, the
// enforcer handed to New receives the same narrowed probe the engine got;
// with it off, the gate is left exactly as run.go built it.
func TestADR0013_GateReceivesNarrowedProbe(t *testing.T) {
	for _, tc := range []struct {
		name      string
		on        bool
		wantCalls int
	}{
		{"require_authenticated on", true, 1},
		{"require_authenticated off", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := store.Open(context.Background(), ":memory:")
			if err != nil {
				t.Fatalf("store.Open: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			policy := &config.Policy{
				Armed:            true,
				BanThreshold:     config.DefaultBanThreshold,
				ObserveThreshold: config.DefaultObserveThreshold,
				MaxBansPerMinute: config.DefaultMaxBansPerMinute,
				Strikes:          config.DefaultStrikes,
			}
			if tc.on {
				policy.AntiLockout = &config.AntiLockoutCfg{RequireAuthenticated: true}
			}
			spy := &probeSpyEnforcer{}
			if _, err := New(Config{Policy: policy, Store: db, Enforcer: spy, SocketPath: ""}); err != nil {
				t.Fatalf("New: %v", err)
			}
			spy.mu.Lock()
			defer spy.mu.Unlock()
			if spy.calls != tc.wantCalls {
				t.Fatalf("SetSSHPeerProbe called %d time(s), want %d", spy.calls, tc.wantCalls)
			}
			if tc.on && spy.probe == nil {
				t.Fatalf("gate received a nil probe — peer check disabled instead of narrowed")
			}
		})
	}
}
