// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// The HTTP transport lives in dockerhost.go (NewDockerAPIClient) so the unix
// and tcp variants — with their dial/header timeouts and their "never follow
// a redirect" policy — are defined once and shared with the exec watcher, the
// daemon's on-demand evidence extraction and doctor.

// runAPI streams the container's stdout+stderr via the Docker Engine API and
// emits one RawLine per '\n'-terminated line. It retries with exponential
// backoff when the container is missing or the stream ends — mirroring the
// filesystem path's semantics for container restarts.
//
// Retrying is bounded, not endless (issue #580): a collector that never
// reaches the Engine API keeps its failure inside this loop, where the daemon
// supervisor cannot see it — status then reports collectors_state OK while
// nothing at all is being observed. A persistent connect failure is returned
// so supervision, the DEGRADED state, the audit row and the critical
// notification all fire, exactly as they do for journald.
func (c *DockerCollector) runAPI(ctx context.Context, ep DockerEndpoint, source string, out chan<- sdk.RawLine, logger *slog.Logger) error {
	client := NewDockerAPIClient(ep)
	defer client.CloseIdleConnections()

	backoff := dockerBackoffBase
	everConnected := false // at least one 200 response during this Run
	failures := 0          // consecutive attempts that never got a stream
	for {
		if ctx.Err() != nil {
			return nil
		}

		connected, err := c.streamAPILogs(ctx, client, source, out)
		if ctx.Err() != nil {
			return nil
		}
		if connected {
			// The stream was live: whatever ended it (container restart,
			// clean EOF) is the in-loop reconnect case.
			everConnected = true
			failures = 0
		}
		if err != nil {
			if !connected {
				failures++
			}
			if fatal := c.fatalAPIError(ep.String(), everConnected, failures, err); fatal != nil {
				return fatal
			}
			logger.Warn("docker api: stream ended; retrying",
				slog.String("container", c.Container),
				slog.String("err", err.Error()),
				slog.Duration("backoff", backoff),
			)
		} else {
			// Clean EOF (e.g., container restarted) — reset backoff so the
			// next reconnect is fast.
			backoff = dockerBackoffBase
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if err != nil {
			backoff = min(backoff*2, dockerBackoffMax)
		}
	}
}

// fatalAPIError decides whether a failed attempt must end Run so the daemon
// supervisor records it (issue #580), or whether the loop keeps reconnecting.
//
// A permission denial is always fatal: it is never a transient stream drop,
// and retrying it forever is precisely the silence this issue removes. Any
// other failure is fatal once the attempt streak crosses the bound for the
// situation — a short one while the collector has never connected (a socket
// blip during `systemctl restart docker` still absorbs), a longer one after a
// stream has worked at least once (a container restarting is normal).
func (c *DockerCollector) fatalAPIError(endpoint string, everConnected bool, failures int, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return dockerPermissionError(endpoint, err)
	}
	limit := maxDockerConnectAttempts
	if everConnected {
		limit = maxDockerReconnectAttempts
	}
	if failures >= limit {
		return fmt.Errorf("docker api: container %q unreadable after %d attempts: %w", c.Container, failures, err)
	}
	return nil
}

// streamAPILogs opens GET /containers/<name>/logs?follow=1 and forwards each
// log line into out. The container name is already validated by the caller
// against reDockerContainerName so it's URL-safe; we still pass it through
// the request path verbatim.
//
// connected reports whether the Engine actually served the stream (a 200
// response). It is what separates "this collector never got off the ground"
// from "a live stream dropped" for the caller's retry policy (issue #580);
// a dial failure or a non-200 answer (403 from a filtering proxy, 404 for a
// missing container) both leave it false.
func (c *DockerCollector) streamAPILogs(ctx context.Context, client *http.Client, source string, out chan<- sdk.RawLine) (connected bool, err error) {
	// Host portion is ignored — the unix transport dials the docker socket.
	// tail=0 = start streaming new lines only (matches the filesystem path's
	// "tail -f"-style behaviour: don't replay history).
	url := "http://docker/containers/" + c.Container + "/logs?follow=true&stdout=true&stderr=true&tail=0"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("docker api: new request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("docker api: request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		// Drain a bounded chunk for HTTP keep-alive cleanliness; don't leak
		// the body into errors (it may include hostile content if a malicious
		// proxy spoofs the response — SECURITY-REVIEW.md §1).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("docker api: HTTP %s", resp.Status)
	}

	return true, parseDockerMultiplexedStream(ctx, resp.Body, source, out)
}

// parseDockerMultiplexedStream consumes Docker's multiplexed logs stream via
// DemuxDockerLogStream (see dockermux.go for the frame layout and bounds)
// and emits one sdk.RawLine per reassembled line.
func parseDockerMultiplexedStream(ctx context.Context, r io.Reader, source string, out chan<- sdk.RawLine) error {
	return DemuxDockerLogStream(ctx, r, func(line []byte) bool {
		// Copy: the demux buffer is reused, but RawLine retains the slice.
		cp := make([]byte, len(line))
		copy(cp, line)
		select {
		case out <- sdk.RawLine{Source: source, Line: cp, At: time.Now()}:
			return false
		case <-ctx.Done():
			return true
		}
	})
}
