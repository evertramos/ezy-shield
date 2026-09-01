// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package collector

// Docker exec activity watcher (issue #220): log-based detection is blind
// to what happens AFTER a successful intrusion. On docker hosts the events
// API emits exec_create/exec_start for every `docker exec` into a container
// — a shell spawned in a web container at 3am is a strong post-exploitation
// indicator no log parser will ever see.
//
// Purely observational: the watcher reports structured exec events to a
// sink; the daemon audits/streams/notifies them. NO ban decisions derive
// from it (there is usually no remote IP to ban). Docker API responses are
// untrusted input: line-bounded reads, strict decode into a fixed struct,
// and hard caps on every string that leaves this file.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"
)

// Exec-event caps: everything below came over the docker socket and may be
// attacker-influenced (a compromised container can restart itself with a
// hostile name; exec commands are arbitrary bytes).
const (
	maxExecEventLineBytes = 16 * 1024
	maxExecCommandBytes   = 256
	maxExecNameBytes      = 128
)

// ExecEvent is one observed `docker exec` into a container.
type ExecEvent struct {
	// Container and Image identify where the exec landed (capped).
	Container string
	Image     string
	// Command is the exec'ed command line as docker reports it (capped,
	// untrusted — sanitize at render time like log content).
	Command string
	// User is the exec user when docker reports one (capped; often empty).
	User string
	// Time is the daemon-side observation time.
	Time time.Time
}

// DockerExecWatcher subscribes to the docker events API and reports
// exec_start events (exec_create is skipped — exec_start is the moment the
// process actually runs, and both carry the same command).
type DockerExecWatcher struct {
	// Ignore lists container-name or image patterns to skip (path.Match
	// globs; a pattern without meta characters matches as substring) —
	// legitimate cron/health tooling.
	Ignore []string
	// Logger receives debug/warn messages. If nil, slog.Default() is used.
	Logger *slog.Logger
	// DockerSocketPath overrides /var/run/docker.sock (tests).
	DockerSocketPath string
	// DockerHost is the configured Engine endpoint in docker.host syntax
	// (unix:///path or tcp://host:port). When set it wins over
	// DockerSocketPath; empty means DefaultDockerHost. The watcher needs
	// /events, so a filtering proxy must expose EVENTS as well as
	// CONTAINERS. See dockerhost.go.
	DockerHost string
}

// endpoint resolves the Engine endpoint this watcher subscribes to.
// DockerHost (operator configuration) wins over DockerSocketPath (the unix
// test hook); an empty pair means the default socket.
func (w *DockerExecWatcher) endpoint() (DockerEndpoint, error) {
	if w.DockerHost != "" {
		return ParseDockerHost(w.DockerHost)
	}
	if w.DockerSocketPath != "" {
		return DockerEndpoint{Scheme: "unix", SocketPath: w.DockerSocketPath}, nil
	}
	return DockerEndpoint{Scheme: "unix", SocketPath: defaultDockerSocketPath}, nil
}

// Name identifies the watcher in supervision logs.
func (w *DockerExecWatcher) Name() string { return "docker-exec-watch" }

// Run streams docker events until ctx is done, reporting each accepted exec
// to sink. It reconnects with capped backoff when a live stream drops (docker
// restarts) and returns nil only on context cancellation.
//
// A connect failure is different from a stream drop (issue #580): if the
// watcher never reaches the events API — permission denied on the socket, a
// filtering proxy answering 403 — retrying here forever means the daemon
// believes exec activity is being watched while nothing is. Those failures
// are returned so the daemon records them like any other observation gap.
func (w *DockerExecWatcher) Run(ctx context.Context, sink func(ExecEvent)) error {
	logger := w.Logger
	if logger == nil {
		logger = slog.Default()
	}
	ep, err := w.endpoint()
	if err != nil {
		return fmt.Errorf("docker-exec: %w", err)
	}
	client := NewDockerAPIClient(ep)
	defer client.CloseIdleConnections()

	backoff := dockerBackoffBase
	everConnected := false // at least one 200 response during this Run
	failures := 0          // consecutive attempts that never got a stream
	for {
		connected, err := w.streamEvents(ctx, client, logger, sink)
		if ctx.Err() != nil {
			return nil
		}
		if connected {
			everConnected = true
			failures = 0
		} else {
			failures++
		}
		if errors.Is(err, fs.ErrPermission) {
			return dockerPermissionError(ep.String(), err)
		}
		limit := maxDockerConnectAttempts
		if everConnected {
			limit = maxDockerReconnectAttempts
		}
		if failures >= limit {
			return fmt.Errorf("docker-exec: events API unreachable after %d attempts: %w", failures, err)
		}
		logger.Warn("docker-exec: event stream dropped; reconnecting",
			"err", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > dockerBackoffMax {
			backoff = dockerBackoffMax
		}
	}
}

// dockerEventEnvelope is the strict subset of a docker event this watcher
// reads; unknown fields are ignored.
type dockerEventEnvelope struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
}

// streamEvents holds one connection to GET /events and processes the
// newline-delimited JSON stream. connected reports whether the Engine served
// the stream (200), which is what tells the caller apart a watcher that never
// started from one whose live stream dropped (issue #580).
func (w *DockerExecWatcher) streamEvents(ctx context.Context, client *http.Client,
	logger *slog.Logger, sink func(ExecEvent)) (connected bool, err error) {
	// Host portion is ignored — the unix transport dials the docker socket.
	// The container-type filter narrows the stream server-side; exec actions
	// are still matched client-side (filter grammar varies across engines).
	url := `http://docker/events?filters=` + `{"type":["container"]}`
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("docker-exec: build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("docker-exec: connect events API: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		// The status line is engine-controlled but bounded; the body is
		// never echoed (SECURITY-REVIEW.md §1).
		return false, fmt.Errorf("docker-exec: events API status %s", resp.Status)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), maxExecEventLineBytes)
	for sc.Scan() {
		if ctx.Err() != nil {
			return true, nil
		}
		w.handleEventLine(sc.Bytes(), logger, sink)
	}
	if err := sc.Err(); err != nil {
		return true, fmt.Errorf("docker-exec: read events: %w", err)
	}
	return true, fmt.Errorf("docker-exec: events stream ended")
}

// handleEventLine decodes one stream line and reports it when it is a
// non-ignored exec_start. Malformed lines are skipped, never fatal.
func (w *DockerExecWatcher) handleEventLine(line []byte, logger *slog.Logger, sink func(ExecEvent)) {
	if len(line) == 0 || len(line) > maxExecEventLineBytes {
		return
	}
	var ev dockerEventEnvelope
	if err := json.Unmarshal(line, &ev); err != nil {
		logger.Debug("docker-exec: malformed event line, skipping", "err", err)
		return
	}
	if ev.Type != "container" {
		return
	}
	// Action is "exec_start: <command>" (exec_create is the setup twin —
	// skipped so each exec reports once, at the moment it actually runs).
	cmd, ok := strings.CutPrefix(ev.Action, "exec_start")
	if !ok {
		return
	}
	cmd = strings.TrimPrefix(strings.TrimSpace(cmd), ":")
	cmd = strings.TrimSpace(cmd)

	name := capExecField(ev.Actor.Attributes["name"], maxExecNameBytes)
	image := capExecField(ev.Actor.Attributes["image"], maxExecNameBytes)
	if w.ignored(name) || w.ignored(image) {
		logger.Debug("docker-exec: ignored by pattern", "container", name)
		return
	}
	sink(ExecEvent{
		Container: name,
		Image:     image,
		Command:   capExecField(cmd, maxExecCommandBytes),
		User:      capExecField(ev.Actor.Attributes["execUser"], maxExecNameBytes),
		Time:      time.Now(),
	})
}

// ignored reports whether value matches any ignore pattern: path.Match
// globs, or plain substring when the pattern has no glob metacharacters.
func (w *DockerExecWatcher) ignored(value string) bool {
	if value == "" {
		return false
	}
	for _, pat := range w.Ignore {
		if pat == "" {
			continue
		}
		if strings.ContainsAny(pat, "*?[") {
			if ok, err := path.Match(pat, value); err == nil && ok {
				return true
			}
			continue
		}
		if strings.Contains(value, pat) {
			return true
		}
	}
	return false
}

// capExecField bounds an attacker-influenced string.
func capExecField(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
