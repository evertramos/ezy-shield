package daemon

// Regression tests for issue #361 item 5: the production shutdown paths —
// SIGTERM graceful drain and SIGINT immediate exit — were untested; every
// daemon test shut down via parent-context cancellation, which takes a
// separate branch, so the drain-before-exit contract documented on Run was
// unverified. Signals are injected through d.sigCh (never raised on the real
// process, which would leak into every other daemon test in this binary).

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// startSignalDaemon builds a minimal daemon with an injected signal channel
// and one fake collector, runs it, and returns the plumbing.
func startSignalDaemon(t *testing.T, lines []sdk.RawLine) (sigCh chan os.Signal, actions chan sdk.Action, done chan error, cancel context.CancelFunc) {
	t.Helper()

	ctx, cancelFn := context.WithCancel(context.Background())
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	policy := &config.Policy{
		Armed:            false,
		BanThreshold:     70,
		ObserveThreshold: 40,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}

	d, err := New(Config{
		Cfg:        &config.Config{},
		Policy:     policy,
		Store:      db,
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default())},
		Collectors: []sdk.Collector{&fakeCollector{lines: lines}},
		SocketPath: "",
		MaxIPs:     100,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sigCh = make(chan os.Signal, 1)
	d.sigCh = sigCh
	actions = make(chan sdk.Action, 32)
	d.SetActionsSink(actions)

	done = make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	return sigCh, actions, done, cancelFn
}

// TestRun_SIGTERMDrainsBeforeExit: SIGTERM must stop the collectors, let the
// pipeline drain in-flight events, and only then return.
func TestRun_SIGTERMDrainsBeforeExit(t *testing.T) {
	attacker := netip.MustParseAddr("198.51.100.91")
	sigCh, actions, done, cancel := startSignalDaemon(t, bruteforceLines(attacker, 6))
	defer cancel()

	// Wait until the pipeline has fully processed the in-flight burst (the
	// attacker's strike action arrives on the sink) — proves lines were
	// flowing when the signal lands.
	select {
	case a := <-actions:
		if a.IP != attacker {
			t.Fatalf("unexpected action %+v", a)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pipeline never processed the in-flight lines")
	}

	sigCh <- syscall.SIGTERM

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error on SIGTERM: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGTERM did not shut the daemon down (drain wedged?)")
	}
}

// TestRun_SIGINTExitsImmediately: SIGINT skips the drain and returns fast.
func TestRun_SIGINTExitsImmediately(t *testing.T) {
	attacker := netip.MustParseAddr("198.51.100.92")
	sigCh, _, done, cancel := startSignalDaemon(t, bruteforceLines(attacker, 2))
	defer cancel()

	// Give the daemon a moment to be inside Run's signal select.
	time.Sleep(50 * time.Millisecond)
	sigCh <- syscall.SIGINT

	start := time.Now()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error on SIGINT: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGINT did not shut the daemon down")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("SIGINT took %v — must be immediate, not a drain", elapsed)
	}
}
