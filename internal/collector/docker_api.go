//go:build linux

package collector

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// newDockerAPIClient returns an http.Client whose transport dials the Docker
// engine unix socket. The Host portion of URLs is ignored; the unix transport
// always dials socketPath.
func newDockerAPIClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// runAPI streams the container's stdout+stderr via the Docker Engine API and
// emits one RawLine per '\n'-terminated line. It retries with exponential
// backoff when the container is missing or the stream ends — mirroring the
// filesystem path's semantics for container restarts.
func (c *DockerCollector) runAPI(ctx context.Context, socketPath, source string, out chan<- sdk.RawLine, logger *slog.Logger) error {
	client := newDockerAPIClient(socketPath)

	backoff := dockerBackoffBase
	for {
		if ctx.Err() != nil {
			return nil
		}

		err := c.streamAPILogs(ctx, client, source, out)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
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

// streamAPILogs opens GET /containers/<name>/logs?follow=1 and forwards each
// log line into out. The container name is already validated by the caller
// against reDockerContainerName so it's URL-safe; we still pass it through
// the request path verbatim.
func (c *DockerCollector) streamAPILogs(ctx context.Context, client *http.Client, source string, out chan<- sdk.RawLine) error {
	// Host portion is ignored — the unix transport dials the docker socket.
	// tail=0 = start streaming new lines only (matches the filesystem path's
	// "tail -f"-style behaviour: don't replay history).
	url := "http://docker/containers/" + c.Container + "/logs?follow=true&stdout=true&stderr=true&tail=0"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("docker api: new request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("docker api: request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		// Drain a bounded chunk for HTTP keep-alive cleanliness; don't leak
		// the body into errors (it may include hostile content if a malicious
		// proxy spoofs the response — SECURITY-REVIEW.md §1).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("docker api: HTTP %s", resp.Status)
	}

	return parseDockerMultiplexedStream(ctx, resp.Body, source, out)
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
