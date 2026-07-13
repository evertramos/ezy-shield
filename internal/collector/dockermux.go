package collector

// Docker Engine API multiplexed log stream demultiplexer. Shared by the
// streaming DockerCollector (docker_api.go) and by the daemon's on-demand
// evidence extraction (issue #126), so the frame-parsing security bounds
// live in exactly one place. No build tag: consumers on any platform can
// parse a captured stream.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// dockerAPIMaxFrameSize caps a single multiplexed-stream frame at 1 MiB. The
// Docker API never sends frames this large for log streams, so this guard is
// only ever tripped by a wedged or hostile docker-compatible server. The cap
// bounds attacker influence over memory (SECURITY-REVIEW.md §1).
const dockerAPIMaxFrameSize = 1 << 20

// DemuxDockerLogStream consumes Docker's multiplexed logs stream (8-byte
// frame headers + payload) and calls emit once per '\n'-terminated line in
// the reassembled stream. A trailing partial line is held between frames and
// dropped at EOF (mirrors the streaming collector's behaviour). The line
// slice passed to emit is only valid for the duration of the call — copy it
// to retain it. If emit returns true, parsing stops and nil is returned.
//
// Frame header layout (Docker remote API):
//
//	byte 0:    stream type (0=stdin, 1=stdout, 2=stderr)
//	bytes 1-3: padding
//	bytes 4-7: payload length (big-endian uint32)
//
// Frames larger than dockerAPIMaxFrameSize are rejected to cap memory use.
// A trailing CR is stripped from CRLF-terminated lines.
func DemuxDockerLogStream(ctx context.Context, r io.Reader, emit func(line []byte) (stop bool)) error {
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
			chunk := line[:idx]
			// Strip optional CR from CRLF endings — some app logs use them
			// and parsers don't expect a literal \r at end-of-line.
			if len(chunk) > 0 && chunk[len(chunk)-1] == '\r' {
				chunk = chunk[:len(chunk)-1]
			}
			if emit(chunk) {
				return nil
			}
			line = line[idx+1:]
		}
	}
}
