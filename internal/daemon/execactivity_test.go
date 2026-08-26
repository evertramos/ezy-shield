package daemon

// Tests for the daemon half of the docker exec activity signal (issue
// #220): observations are audited and notified, the injected watcher is
// started by Run's goroutine set, and — the core safety property — nothing
// about an exec observation ever creates a ban.

import (
	"context"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
)

func newExecDaemon(t *testing.T, watch func(ctx context.Context, report func(ExecActivityReport))) (*Daemon, *store.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d, err := New(Config{
		Policy: &config.Policy{
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:        db,
		SocketPath:   "",
		ExecActivity: watch,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, db
}

func TestReportExecActivity_AuditsAndStaysObservational(t *testing.T) {
	d, db := newExecDaemon(t, nil)
	ctx := context.Background()

	d.ReportExecActivity(ctx, ExecActivityReport{
		Container: "web-1", Image: "nginx:latest",
		Command: "/bin/sh -c id", User: "root",
	})

	entries, err := db.ListAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Op == "docker_exec" {
			found = true
			for _, want := range []string{"web-1", "nginx:latest", "/bin/sh -c id", "root"} {
				if !strings.Contains(e.Reason, want) {
					t.Errorf("audit reason %q lacks %q", e.Reason, want)
				}
			}
		}
	}
	if !found {
		t.Fatal("no docker_exec audit entry written")
	}

	// The core safety property: purely observational — no ban anywhere.
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 0 {
		t.Fatalf("exec observation created a ban: %+v", bans)
	}
}

func TestRunExecActivity_StartsInjectedWatcher(t *testing.T) {
	started := make(chan struct{})
	d, db := newExecDaemon(t, func(ctx context.Context, report func(ExecActivityReport)) {
		report(ExecActivityReport{Container: "c1", Image: "i1", Command: "cmd"})
		close(started)
		<-ctx.Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.runExecActivity(ctx)
	<-started

	entries, err := db.ListAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Op == "docker_exec" && strings.Contains(e.Reason, "c1") {
			found = true
		}
	}
	if !found {
		t.Fatal("injected watcher's report did not reach the audit log")
	}
}

func TestRunExecActivity_NilWatcherIsDormant(t *testing.T) {
	d, _ := newExecDaemon(t, nil)
	d.runExecActivity(context.Background()) // must return immediately, no panic
}
