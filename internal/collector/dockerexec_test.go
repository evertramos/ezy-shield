// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package collector

// Tests for the docker exec activity watcher (issue #220), against a fake
// docker events API served on a unix socket: normal exec, skipped
// exec_create, ignore patterns, malformed events, oversized lines, and
// reconnect after a dropped stream.

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDockerEvents serves GET /events on a unix socket. Each call to the
// handler writes the next batch of lines and either holds the stream open
// until ctx ends or closes it (to exercise reconnect).
func fakeDockerEvents(t *testing.T, batches [][]string) (sock string, conns *atomic.Int32) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "docker.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	conns = new(atomic.Int32)
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/events") {
			http.NotFound(w, r)
			return
		}
		n := int(conns.Add(1)) - 1
		fl, _ := w.(http.Flusher)
		if n < len(batches) {
			for _, line := range batches[n] {
				_, _ = io.WriteString(w, line+"\n")
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if n+1 < len(batches) {
			return // close the stream — the watcher must reconnect
		}
		<-r.Context().Done() // last batch: hold open until the client goes away
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock, conns
}

func execLine(action, name, image string) string {
	return `{"Type":"container","Action":"` + action + `","Actor":{"ID":"cid","Attributes":{"name":"` + name + `","image":"` + image + `","execID":"e1"}}}`
}

func TestDockerExecWatcher_EmitsAndFilters(t *testing.T) {
	sock, _ := fakeDockerEvents(t, [][]string{{
		execLine("exec_start: /bin/sh -c id", "web-1", "nginx:latest"),
		execLine("exec_create: /bin/sh -c id", "web-1", "nginx:latest"),          // setup twin — skipped
		execLine("exec_start: /usr/bin/healthcheck", "web-1", "healthcheck-img"), // ignored by image pattern
		execLine("exec_start: cat /etc/passwd", "cron-runner", "busybox"),        // ignored by name substring
		execLine("start", "web-1", "nginx:latest"),                               // unrelated action
		`{"Type":"network","Action":"exec_start: nope"}`,                         // wrong type
		`{not json`, // malformed — skipped
		execLine("exec_start", "web-2", "redis:7"), // no command suffix
	}})

	w := &DockerExecWatcher{
		Ignore:           []string{"cron-*", "healthcheck"},
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		DockerSocketPath: sock,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan ExecEvent, 8)
	go func() { _ = w.Run(ctx, func(ev ExecEvent) { got <- ev }) }()

	var events []ExecEvent
	timeout := time.After(5 * time.Second)
	for len(events) < 2 {
		select {
		case ev := <-got:
			events = append(events, ev)
		case <-timeout:
			t.Fatalf("timed out with %d events: %+v", len(events), events)
		}
	}
	cancel()

	if events[0].Container != "web-1" || events[0].Command != "/bin/sh -c id" || events[0].Image != "nginx:latest" {
		t.Fatalf("first event = %+v", events[0])
	}
	if events[1].Container != "web-2" || events[1].Command != "" {
		t.Fatalf("second event = %+v (bare exec_start has no command)", events[1])
	}
	select {
	case ev := <-got:
		t.Fatalf("unexpected extra event: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestDockerExecWatcher_ReconnectsAfterDrop(t *testing.T) {
	sock, conns := fakeDockerEvents(t, [][]string{
		{execLine("exec_start: first", "app", "img")},
		{execLine("exec_start: second", "app", "img")},
	})
	w := &DockerExecWatcher{
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		DockerSocketPath: sock,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan ExecEvent, 4)
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, func(ev ExecEvent) { got <- ev }) }()

	var cmds []string
	timeout := time.After(10 * time.Second)
	for len(cmds) < 2 {
		select {
		case ev := <-got:
			cmds = append(cmds, ev.Command)
		case <-timeout:
			t.Fatalf("timed out after %d events (conns=%d)", len(cmds), conns.Load())
		}
	}
	if cmds[0] != "first" || cmds[1] != "second" {
		t.Fatalf("cmds = %v", cmds)
	}
	if conns.Load() < 2 {
		t.Fatalf("watcher did not reconnect: %d connection(s)", conns.Load())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run must return nil on cancellation, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestDockerExecWatcher_CapsHostileFields(t *testing.T) {
	long := strings.Repeat("x", 5000)
	sock, _ := fakeDockerEvents(t, [][]string{{
		execLine("exec_start: "+long, "name-"+long, "img"),
	}})
	w := &DockerExecWatcher{
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		DockerSocketPath: sock,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan ExecEvent, 1)
	go func() { _ = w.Run(ctx, func(ev ExecEvent) { got <- ev }) }()
	select {
	case ev := <-got:
		if len(ev.Command) != maxExecCommandBytes || len(ev.Container) != maxExecNameBytes {
			t.Fatalf("caps not applied: cmd=%d name=%d", len(ev.Command), len(ev.Container))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}
