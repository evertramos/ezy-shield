// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package collector_test

// Tests for issue #580: a docker collector that cannot reach the Engine API
// must return the failure from Run so the daemon supervisor sees it —
// collectors_state DEGRADED, audit row, critical notification — instead of
// retrying forever inside its own loop while status keeps claiming a healthy
// observation path. Reconnecting stays in-loop for the case it was written
// for: a stream that dropped after it had worked.

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/collector"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// unreadableSocket creates a real unix socket and closes it to every access
// path, reproducing the field condition: the socket is there, the service
// user is denied. Root ignores mode bits, so the test is skipped for root.
func unreadableSocket(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny access, the denial cannot be reproduced")
	}
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := os.Chmod(sock, 0o000); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}
	return sock
}

// assertPermissionHint checks the operator-facing content of the error: whose
// access is missing, and the three ways to grant it with their cost.
func assertPermissionHint(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	for _, want := range []string{
		"permission denied",
		"ezyshield",        // the service user, not whoever ran the process
		"host-mounted log", // path 1
		"socket proxy",     // path 2
		"'docker' group",   // path 3
		"root-equivalent",  // its cost
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestDockerCollector_UnreadableSocketReturnsPermissionError is the core
// regression: on origin/dev this Run never returns and the daemon reports
// collectors_state OK while the collector reads nothing.
func TestDockerCollector_UnreadableSocketReturnsPermissionError(t *testing.T) {
	sock := unreadableSocket(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c := &collector.DockerCollector{
		Container:        "proxy-web",
		Parser:           "nginx",
		Logger:           testLogger(t),
		DockerSocketPath: sock,
		// If the collector ever fell back to the filesystem path it would
		// exec this; the script does not exist, which would show up as a
		// different (inspect) error than the permission one asserted below.
		DockerCmd: filepath.Join(t.TempDir(), "no-such-docker"),
	}

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, make(chan sdk.RawLine, 1)) }()

	select {
	case err := <-done:
		assertPermissionHint(t, err)
	case <-ctx.Done():
		t.Fatal("Run never returned on a permission-denied socket: the failure stays invisible to the supervisor")
	}
}

// TestDockerCollector_UnstattableSocketDoesNotFallBackToFilesystem covers the
// EACCES-on-stat variant (a parent directory that denies traversal). The
// filesystem fallback reads /var/lib/docker, which is closed for the same
// reason, so falling back would only replace a clear denial with a vague one.
func TestDockerCollector_UnstattableSocketDoesNotFallBackToFilesystem(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory mode bits do not deny traversal")
	}
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	sock := filepath.Join(dir, "docker.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	// Restore traversal so t.TempDir's cleanup can remove the directory.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: a directory needs its execute bit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := &collector.DockerCollector{
		Container:        "proxy-web",
		Logger:           testLogger(t),
		DockerSocketPath: sock,
		DockerCmd:        filepath.Join(t.TempDir(), "no-such-docker"),
	}

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, make(chan sdk.RawLine, 1)) }()

	select {
	case err := <-done:
		assertPermissionHint(t, err)
	case <-ctx.Done():
		t.Fatal("Run did not report the unreachable socket; it fell back instead of failing honestly")
	}
}

// TestDockerCollector_MissingContainerReturnsAfterBoundedRetries proves a
// non-200 answer (404 for a container that does not exist, 403 from a
// filtering proxy) is propagated after a short in-loop retry, rather than
// retried forever.
func TestDockerCollector_MissingContainerReturnsAfterBoundedRetries(t *testing.T) {
	sock, conns := notFoundDockerAPI(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := &collector.DockerCollector{
		Container:        "gone",
		Logger:           testLogger(t),
		DockerSocketPath: sock,
	}

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, make(chan sdk.RawLine, 1)) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for a container the engine does not serve")
		}
		if !strings.Contains(err.Error(), "404") {
			t.Errorf("error %q does not carry the HTTP status", err)
		}
		// The retry is short but real: a single blip must not end the run.
		if got := conns.Load(); got < 2 {
			t.Errorf("gave up after %d attempt(s); a transient failure deserves a retry", got)
		}
	case <-ctx.Done():
		t.Fatal("Run never returned for a container the engine does not serve")
	}
}

// TestDockerCollector_StreamDropAfterConnectRetriesInLoop guards the
// behaviour that must NOT change: a container restart drops the stream, and
// the collector reconnects on its own instead of failing the whole Run.
func TestDockerCollector_StreamDropAfterConnectRetriesInLoop(t *testing.T) {
	sock, conns := droppingDockerAPI(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := &collector.DockerCollector{
		Container:        "proxy-web",
		Logger:           testLogger(t),
		DockerSocketPath: sock,
	}

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, make(chan sdk.RawLine, 8)) }()

	deadline := time.After(15 * time.Second)
	for conns.Load() < 3 {
		select {
		case err := <-done:
			t.Fatalf("Run returned %v after %d reconnect(s); stream drops must be retried in-loop",
				err, conns.Load())
		case <-deadline:
			t.Fatalf("only %d connection(s) after 15s; the collector is not reconnecting", conns.Load())
		case <-time.After(50 * time.Millisecond):
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("clean shutdown must return nil, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestDockerExecWatcher_UnreadableSocketReturnsPermissionError: the exec
// watcher has the same in-loop retry and the same blind spot.
func TestDockerExecWatcher_UnreadableSocketReturnsPermissionError(t *testing.T) {
	sock := unreadableSocket(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	w := &collector.DockerExecWatcher{
		Logger:           testLogger(t),
		DockerSocketPath: sock,
	}

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, func(collector.ExecEvent) {}) }()

	select {
	case err := <-done:
		assertPermissionHint(t, err)
	case <-ctx.Done():
		t.Fatal("exec watcher never returned on a permission-denied socket")
	}
}

// notFoundDockerAPI serves 404 for every request and counts the attempts.
func notFoundDockerAPI(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	conns := new(atomic.Int32)
	return serveDockerAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		conns.Add(1)
		http.Error(w, "No such container", http.StatusNotFound)
	}), conns
}

// droppingDockerAPI answers 200 with one complete log frame and then ends the
// response — the shape of a container restart.
func droppingDockerAPI(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	conns := new(atomic.Int32)
	frame := dockerLogFrame(1, []byte("192.0.2.7 - - GET / 200\n"))
	return serveDockerAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		conns.Add(1)
		w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(frame)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Returning ends the response body: the client sees a clean EOF.
	}), conns
}

// serveDockerAPI starts h on a unix socket in a temp dir and returns its path.
func serveDockerAPI(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen mock docker socket: %v", err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}
