// SPDX-License-Identifier: AGPL-3.0-only

// Package e2e is the integration harness of issue #605: the REAL store,
// decision engine, daemon, enforcer client and enforcer helper chained over
// a unix socket against a scripted kernel (internal/enforcerd/nfttest), all
// on one virtual clock. Every scenario here pins an invariant from
// docs/internal/INVARIANTS.md; a fix to a reader or writer of that
// invariant must keep these green and add its own failing-first scenario.
//
// Tests in this package share the process-wide `nft list set` hook and must
// not run in parallel.
package e2e

import (
	"context"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/daemon"
	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/enforcerd"
	"github.com/evertramos/ezy-shield/internal/enforcerd/nfttest"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// clock is the single virtual clock shared by every component.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// peers is a settable SSH-peer source for the engine and/or the gate.
type peers struct {
	mu   sync.Mutex
	list []netip.Addr
}

func (p *peers) set(a ...netip.Addr) { p.mu.Lock(); p.list = a; p.mu.Unlock() }
func (p *peers) probe() []netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netip.Addr(nil), p.list...)
}

// system is one fully wired EzyShield: helper + kernel + daemon + store.
type system struct {
	t       *testing.T
	ctx     context.Context
	clock   *clock
	kernel  *nfttest.Kernel
	helper  *enforcerd.Server
	daemon  *daemon.Daemon
	store   *store.DB
	actions chan sdk.Action
	engine  *peers // engine-side SSH peers (ADR-0013 narrowed view)
	gate    *peers // gate-side SSH peers (kernel view)
}

type options struct {
	armed     bool
	allowlist []string
	seed      func(k *nfttest.Kernel) // runs BEFORE the helper starts
}

// start boots the helper on a temp socket, then the daemon on it, and runs
// the daemon's boot reconcile (allowlist mirror + ban set).
func start(t *testing.T, o options) *system {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clk := &clock{t: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	k := nfttest.New(clk.now)
	if o.seed != nil {
		o.seed(k)
	}
	sock := filepath.Join(t.TempDir(), "enf.sock")

	srv := enforcerd.NewServer(sock, k.Runner())
	srv.SetClock(clk.now)
	srv.SetSessionKiller(func(context.Context, []string) error { return nil })
	t.Cleanup(enforcerd.SetListSetOutput(k.ListSetOutput))
	if err := srv.Listen(ctx); err != nil {
		t.Fatalf("helper listen: %v", err)
	}
	if err := srv.Init(ctx); err != nil {
		t.Fatalf("helper init: %v", err)
	}
	go func() { _ = srv.Serve(ctx) }()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var allow []netip.Prefix
	for _, s := range o.allowlist {
		allow = append(allow, netip.MustParsePrefix(s))
	}
	eng, gate := &peers{}, &peers{}
	enf := enforce.NewGate(enforce.New(sock, allow), allow, gate.probe)

	pol := &config.Policy{
		Armed:            o.armed,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
		Allowlist:        o.allowlist,
	}
	d, err := daemon.New(daemon.Config{
		Policy:     pol,
		Store:      db,
		Enforcer:   enf,
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default()), parser.NewNginxParser(slog.Default(), parser.NginxConfig{})},
		SocketPath: "",
		MaxIPs:     100,
		Now:        clk.now,
	})
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	d.SetSSHPeerProbe(eng.probe)
	actions := make(chan sdk.Action, 256)
	d.SetActionsSink(actions)

	if err := d.ReconcileAllowlist(ctx); err != nil {
		t.Fatalf("boot allowlist reconcile: %v", err)
	}
	if err := d.Reconcile(ctx); err != nil {
		t.Fatalf("boot reconcile: %v", err)
	}
	return &system{t: t, ctx: ctx, clock: clk, kernel: k, helper: srv, daemon: d, store: db, actions: actions, engine: eng, gate: gate}
}

// sshBurst feeds n SSH password failures from ip at the current clock.
func (s *system) sshBurst(ip netip.Addr, n int) {
	for i := 0; i < n; i++ {
		s.daemon.ProcessRaw(s.ctx, sdk.RawLine{
			Source: "journald:sshd",
			Line:   []byte("Failed password for root from " + ip.String() + " port 40122 ssh2"),
			At:     s.clock.now(),
		})
	}
}

// lastAction drains the sink and returns the last action for ip with op.
func (s *system) lastAction(ip netip.Addr, op string) (sdk.Action, bool) {
	var got sdk.Action
	found := false
	for {
		select {
		case a := <-s.actions:
			if a.IP == ip && a.Op == op {
				got, found = a, true
			}
		default:
			return got, found
		}
	}
}

// firstDecision drains the sink and returns the first ban-band decision
// (ban / dry_ban / already_banned) for ip — the one that shows whether the
// engine treated the burst as new evidence or as traffic under a live ban.
func (s *system) firstDecision(ip netip.Addr) (sdk.Action, bool) {
	var got sdk.Action
	found := false
	for {
		select {
		case a := <-s.actions:
			if !found && a.IP == ip && (a.Op == "ban" || a.Op == "dry_ban" || a.Op == "already_banned") {
				got, found = a, true
			}
		default:
			return got, found
		}
	}
}

func (s *system) blocked() []string { return s.kernel.Elements("blocked") }

func contains(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}

// scriptsSince counts kernel scripts applied after mark.
func (s *system) scriptsSince(mark int) int { return len(s.kernel.Scripts) - mark }
