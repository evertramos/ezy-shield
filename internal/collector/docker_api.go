//go:build linux

package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// dockerAPIMaxFrameSize caps a single multiplexed-stream frame at 1 MiB. The
// Docker API never sends frames this large for log streams, so this guard is
// only ever tripped by a wedged or hostile docker-compatible server. The cap
// bounds attacker influence over goroutine memory (SECURITY-REVIEW.md §1).
const dockerAPIMaxFrameSize = 1 << 20

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

// parseDockerMultiplexedStream consumes Docker's logs stream (multiplexed
// 8-byte frame headers + payload) and emits one sdk.RawLine per '\n' in the
// reassembled stream. A trailing partial line is held between frames.
//
// Frame header layout (Docker remote API):
//
//	byte 0:    stream type (0=stdin, 1=stdout, 2=stderr)
//	bytes 1-3: padding
//	bytes 4-7: payload length (big-endian uint32)
//
// Frames larger than dockerAPIMaxFrameSize are rejected to cap memory use.
func parseDockerMultiplexedStream(ctx context.Context, r io.Reader, source string, out chan<- sdk.RawLine) error {
	br := bufio.NewReaderSize(r, 32*1024)
	header := make([]byte, 8)
	var line []byte

	for {
		if ctx.Err() != nil {
			return nil
		}

		if _, err := io.ReadFull(br, header); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return fmt.Errorf("docker api: read header: %w", err)
		}

		size := binary.BigEndian.Uint32(header[4:8])
		if size == 0 {
			continue
		}
		if size > dockerAPIMaxFrameSize {
			return fmt.Errorf("docker api: frame size %d exceeds cap %d", size, dockerAPIMaxFrameSize)
		}

		payload := make([]byte, size)
		if _, err := io.ReadFull(br, payload); err != nil {
			return fmt.Errorf("docker api: read payload: %w", err)
		}

		line = append(line, payload...)
		for {
			idx := bytes.IndexByte(line, '\n')
			if idx < 0 {
				break
			}
			emit := make([]byte, idx)
			copy(emit, line[:idx])
			// Strip optional CR from CRLF endings — some app logs use them
			// and parsers don't expect a literal \r at end-of-line.
			if len(emit) > 0 && emit[len(emit)-1] == '\r' {
				emit = emit[:len(emit)-1]
			}
			select {
			case out <- sdk.RawLine{Source: source, Line: emit, At: time.Now()}:
			case <-ctx.Done():
				return nil
			}
			line = line[idx+1:]
		}
	}
}
