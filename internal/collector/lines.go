package collector

import (
	"bufio"
	"bytes"
	"io"
)

// ── oversized-line-safe stream reading (issue #306) ─────────────────────────
//
// bufio.Scanner stops permanently at its token cap (64 KiB by default): one
// hostile oversized log line ends the scan loop, and a follow-mode
// journalctl then blocks the collector goroutine in cmd.Wait forever —
// untrusted log content silently disabling detection (SECURITY-REVIEW §1:
// length caps; skip/truncate, never die). forEachLine replaces Scanner in
// the subprocess-tailing collectors: lines longer than maxStreamLineBytes
// are truncated (the remainder of the line is drained and discarded, the
// stream keeps flowing), and every complete line is delivered.

// maxStreamLineBytes caps a single delivered log line. Far above any
// legitimate log line, far below memory-exhaustion territory; parsers apply
// their own per-field caps downstream.
const maxStreamLineBytes = 128 * 1024

// forEachLine reads newline-delimited lines from r and calls emit for each,
// with truncated=true when the line exceeded maxLine and was cut there. The
// line slice is only valid during the emit call (callers copy, as they
// already did with Scanner). A trailing line without a newline is delivered
// before returning. Returns nil on EOF, the read error otherwise.
func forEachLine(r io.Reader, maxLine int, emit func(line []byte, truncated bool)) error {
	br := bufio.NewReaderSize(r, 64*1024)
	buf := make([]byte, 0, 4096)
	truncated := false

	flush := func() {
		line := bytes.TrimSuffix(buf, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		emit(line, truncated)
		buf = buf[:0]
		truncated = false
	}

	for {
		chunk, err := br.ReadSlice('\n')
		if room := maxLine - len(buf); room > 0 {
			if len(chunk) > room {
				buf = append(buf, chunk[:room]...)
				truncated = true
			} else {
				buf = append(buf, chunk...)
			}
		} else if len(chunk) > 0 {
			truncated = true // drain the rest of an already-capped line
		}

		switch err {
		case nil:
			flush()
		case bufio.ErrBufferFull:
			continue // mid-line: keep reading (and draining past the cap)
		case io.EOF:
			if len(buf) > 0 {
				flush()
			}
			return nil
		default:
			// Deliver what we have so a crash mid-line still counts, then
			// surface the real error to the caller.
			if len(buf) > 0 {
				flush()
			}
			return err
		}
	}
}
