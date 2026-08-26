// SPDX-License-Identifier: AGPL-3.0-only

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

// lineAssembler accumulates arbitrary chunks into newline-delimited lines
// with a hard per-line cap (issue #307). Unlike a plain append-until-newline
// buffer, content past the cap is discarded while newline scanning
// continues on the full chunk — so a newline-free flood cannot grow memory,
// and a late newline still terminates the (truncated) line at the right
// place instead of gluing lines together. Zero value is NOT ready: use
// newLineAssembler.
type lineAssembler struct {
	max  int
	line []byte
}

func newLineAssembler(maxLine int) *lineAssembler {
	return &lineAssembler{max: maxLine, line: make([]byte, 0, 4096)}
}

// feed scans chunk and calls emit once per completed line (CR of a CRLF
// ending stripped; line capped at max bytes). The emitted slice is only
// valid during the call. Returns true when emit requested a stop.
func (a *lineAssembler) feed(chunk []byte, emit func(line []byte) (stop bool)) bool {
	rest := chunk
	for {
		idx := bytes.IndexByte(rest, '\n')
		seg := rest
		if idx >= 0 {
			seg = rest[:idx]
		}
		if room := a.max - len(a.line); room > 0 {
			if len(seg) > room {
				seg = seg[:room]
			}
			a.line = append(a.line, seg...)
		}
		if idx < 0 {
			return false
		}
		l := a.line
		if len(l) > 0 && l[len(l)-1] == '\r' {
			l = l[:len(l)-1]
		}
		if emit(l) {
			return true
		}
		a.line = a.line[:0]
		rest = rest[idx+1:]
	}
}

// discard drops a buffered partial line (log rotation replaced the file
// mid-line — the fragment belongs to the old file).
func (a *lineAssembler) discard() { a.line = a.line[:0] }

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
