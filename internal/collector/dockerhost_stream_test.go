// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package collector_test

// End-to-end streaming through both docker.host transports (issue #579): the
// same multiplexed-frame payload must arrive identically whether the Engine
// API is reached over a unix socket or over a tcp read-only proxy, and the
// exec watcher's /events stream must work over tcp too.
//
// The negative case matters as much: a hostile endpoint's response body must
// never surface in anything the daemon logs (SECURITY-REVIEW.md §1).

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/collector"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// mockEngineHandler answers the two Engine API endpoints the collectors use.
// logs holds the raw (already framed) log payload; events the newline-
// delimited event lines.
func mockEngineHandler(logs []byte, events []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/containers/") && strings.HasSuffix(r.URL.Path, "/logs"):
			w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(logs)
		case r.URL.Path == "/events":
			w.WriteHeader(http.StatusOK)
			for _, line := range events {
				_, _ = w.Write([]byte(line + "\n"))
			}
		default:
			http.NotFound(w, r)
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done() // hold the stream open until the client leaves
	})
}

// startEngineOverUnix serves mockEngineHandler on a unix socket and returns a
// docker.host value pointing at it.
func startEngineOverUnix(t *testing.T, h http.Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "unix://" + sock
}

// startEngineOverTCP serves mockEngineHandler on loopback tcp — the shape of a
// read-only socket proxy — and returns a docker.host value pointing at it.
func startEngineOverTCP(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return "tcp://" + srv.Listener.Addr().String()
}

// TestDockerCollector_StreamsOverBothTransports runs the identical payload
// through both endpoints via the same collector.
func TestDockerCollector_StreamsOverBothTransports(t *testing.T) {
	const line1 = `192.0.2.1 - - [15/Jan/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 1`
	const line2 = `198.51.100.9 - - [15/Jan/2025:10:00:02 +0000] "GET /.env HTTP/1.1" 404 0`
	payload := dockerLogFrame(1, []byte(line1+"\n"+line2+"\n"))

	tests := []struct {
		name  string
		start func(*testing.T, http.Handler) string
	}{
		{"unix socket", startEngineOverUnix},
		{"tcp read-only proxy", startEngineOverTCP},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host := tc.start(t, mockEngineHandler(payload, nil))

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			out := make(chan sdk.RawLine, 8)
			c := &collector.DockerCollector{
				Container:  "proxy-web",
				Parser:     "nginx",
				Logger:     testLogger(t),
				DockerHost: host,
			}
			done := make(chan error, 1)
			go func() { done <- c.Run(ctx, out) }()

			var got []sdk.RawLine
			deadline := time.After(4 * time.Second)
			for len(got) < 2 {
				select {
				case rl := <-out:
					got = append(got, rl)
				case <-deadline:
					t.Fatalf("timed out with %d lines via %s", len(got), host)
				}
			}
			cancel()
			<-done

			if string(got[0].Line) != line1 || string(got[1].Line) != line2 {
				t.Errorf("lines = %q / %q, want %q / %q", got[0].Line, got[1].Line, line1, line2)
			}
			if got[0].Source != "nginx:proxy-web" {
				t.Errorf("source = %q, want %q", got[0].Source, "nginx:proxy-web")
			}
		})
	}
}

// TestDockerCollector_TCPErrorNeverLeaksBody: an endpoint that answers with an
// error status is untrusted. Its body must not reach the daemon's logs, where
// it would become an injection vector into whatever reads them.
func TestDockerCollector_TCPErrorNeverLeaksBody(t *testing.T) {
	const hostile = "HOSTILE-BODY-MARKER\nlevel=INFO msg=\"forged log line\""

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(hostile))
	}))
	t.Cleanup(srv.Close)

	var mu sync.Mutex
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&syncWriter{mu: &mu, buf: &logBuf}, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out := make(chan sdk.RawLine, 1)
	c := &collector.DockerCollector{
		Container:  "web",
		Logger:     logger,
		DockerHost: "tcp://" + srv.Listener.Addr().String(),
	}
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, out) }()
	<-ctx.Done()
	<-done

	mu.Lock()
	logged := logBuf.String()
	mu.Unlock()

	if !strings.Contains(logged, "HTTP 500") {
		t.Errorf("the failure was not reported at all; log: %q", logged)
	}
	if strings.Contains(logged, "HOSTILE-BODY-MARKER") {
		t.Errorf("response body leaked into the log: %q", logged)
	}
}

// TestDockerExecWatcher_EventsOverTCP: the exec watcher shares the transport,
// so a proxy exposing EVENTS serves it exactly like the socket does.
func TestDockerExecWatcher_EventsOverTCP(t *testing.T) {
	const ev = `{"Type":"container","Action":"exec_start: /bin/sh -c id",` +
		`"Actor":{"ID":"cid","Attributes":{"name":"web-1","image":"nginx:latest"}}}`

	host := startEngineOverTCP(t, mockEngineHandler(nil, []string{ev}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan collector.ExecEvent, 4)
	w := &collector.DockerExecWatcher{
		Logger:     testLogger(t),
		DockerHost: host,
	}
	go func() { _ = w.Run(ctx, func(e collector.ExecEvent) { got <- e }) }()

	select {
	case e := <-got:
		if e.Container != "web-1" {
			t.Errorf("container = %q, want %q", e.Container, "web-1")
		}
		if e.Command != "/bin/sh -c id" {
			t.Errorf("command = %q, want %q", e.Command, "/bin/sh -c id")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an exec event over tcp")
	}
}

// TestDockerCollector_InvalidHostFailsFast: a docker.host the config layer
// would have rejected must not silently fall back to the default socket.
func TestDockerCollector_InvalidHostFailsFast(t *testing.T) {
	c := &collector.DockerCollector{
		Container:  "web",
		Logger:     testLogger(t),
		DockerHost: "ssh://docker@192.0.2.10",
	}
	if err := c.Run(context.Background(), make(chan sdk.RawLine, 1)); err == nil {
		t.Fatal("Run returned nil for an unsupported docker.host scheme")
	}

	w := &collector.DockerExecWatcher{
		Logger:     testLogger(t),
		DockerHost: "ssh://docker@192.0.2.10",
	}
	if err := w.Run(context.Background(), func(collector.ExecEvent) {}); err == nil {
		t.Fatal("exec watcher Run returned nil for an unsupported docker.host scheme")
	}
}

// syncWriter serialises writes from the collector's goroutines so the test can
// read the buffer without racing them.
type syncWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
