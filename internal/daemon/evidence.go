package daemon

// On-demand log evidence extraction for the report verb (issues #54, #126).
//
// When a per-IP report is requested with Evidence set, the daemon re-reads
// its configured log sources and extracts the most recent lines mentioning
// the target address: file sources are scanned directly, journald sources
// via a bounded `journalctl` subprocess, docker sources via the Engine API
// (see evidence_ondemand.go). Nothing is persisted: evidence lives only in
// the response, and when a source cannot be read (log rotated away, socket
// unreachable) the report says so instead of pretending (honest degradation).
//
// Security (§1 SECURITY-REVIEW): extracted lines are hostile bytes and are
// shipped verbatim inside the JSON payload (encoding/json escapes control
// bytes on the wire); terminal/markdown consumers must sanitize before
// rendering (see sdk.AbuseReportEvidence). Bounds below keep the read
// O(window) per source regardless of log size, so the verb cannot be used
// to stall the daemon.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	// evidenceMaxLines caps how many matching lines one source contributes.
	// The scan keeps the most recent matches (the tail of the file).
	evidenceMaxLines = 50
	// evidenceMaxLineBytes truncates individual log lines. Longer lines are
	// kept but cut; oversized hostile lines cannot balloon the response.
	evidenceMaxLineBytes = 2048
	// evidenceWindowBytes bounds how much of each file is scanned: only the
	// trailing window is read, so multi-GB logs cost the same as small ones.
	evidenceWindowBytes = 16 << 20 // 16 MiB
	// evidenceOverallTimeout bounds the whole evidence pass. The control
	// socket enforces a 10s connection deadline (connDeadline); evidence must
	// leave headroom for the store queries and response write.
	evidenceOverallTimeout = 6 * time.Second
	// evidenceSourceTimeout bounds each journald/docker extraction so one
	// wedged subprocess or socket cannot eat the whole evidence budget
	// (a cold journal seek can take a couple of seconds; partial results
	// are kept with an explanatory note when the timeout hits).
	evidenceSourceTimeout = 3 * time.Second
)

// collectEvidence extracts log excerpts mentioning addr from every
// configured log source. It never fails the report: per-source errors
// become notes.
func (d *Daemon) collectEvidence(ctx context.Context, addr netip.Addr) []sdk.AbuseReportEvidence {
	if d.cfg == nil || len(d.cfg.Collectors) == 0 {
		return []sdk.AbuseReportEvidence{{
			Source: "none",
			Note:   "no log sources configured",
		}}
	}

	ctx, cancel := context.WithTimeout(ctx, evidenceOverallTimeout)
	defer cancel()

	out := make([]sdk.AbuseReportEvidence, 0, len(d.cfg.Collectors))
	for _, c := range d.cfg.Collectors {
		if err := ctx.Err(); err != nil {
			break
		}
		switch c.Kind {
		case "file":
			out = append(out, evidenceFromFile(ctx, c.Path, addr))
		case "journald":
			out = append(out, evidenceFromJournald(ctx, d.evidenceJournalctl, c.Unit, addr))
		case "docker":
			out = append(out, evidenceFromDocker(ctx, d.evidenceDockerSocket, c.Container, addr))
		}
	}
	return out
}

// evidenceFromFile scans the trailing window of one log file for lines
// mentioning addr, returning the most recent evidenceMaxLines matches in
// file order. Errors degrade to a note — a rotated log must not fail the
// whole report.
func evidenceFromFile(ctx context.Context, path string, addr netip.Addr) sdk.AbuseReportEvidence {
	ev := sdk.AbuseReportEvidence{Source: "file:" + path}

	f, err := os.Open(path) // #nosec G304 -- path comes from the operator's own config, not from request input
	if err != nil {
		ev.Note = "log not readable (rotated away or removed?)"
		return ev
	}
	defer f.Close() //nolint:errcheck // read-only handle

	info, err := f.Stat()
	if err != nil {
		ev.Note = fmt.Sprintf("stat failed: %v", err)
		return ev
	}
	skipPartial := false
	if info.Size() > evidenceWindowBytes {
		if _, err := f.Seek(-evidenceWindowBytes, io.SeekEnd); err != nil {
			ev.Note = fmt.Sprintf("seek failed: %v", err)
			return ev
		}
		ev.Truncated = true
		ev.Note = "large log: only the most recent portion was scanned"
		skipPartial = true // the first line of the window is almost surely partial
	}

	scanForAddr(ctx, f, addr, skipPartial, &ev)
	if len(ev.Lines) == 0 && ev.Note == "" {
		ev.Note = "no lines mentioning this address (log may have rotated since the strikes)"
	}
	return ev
}

// scanForAddr reads r line by line and appends the lines mentioning addr to
// ev, applying all evidence caps (line length, keep-newest window). When
// skipPartial is set, the first line is discarded — used after seeking into
// the middle of a file. On cancellation it sets an explanatory note and
// returns; on read errors it keeps whatever was extracted so far.
func scanForAddr(ctx context.Context, r io.Reader, addr netip.Addr, skipPartial bool, ev *sdk.AbuseReportEvidence) {
	needle := addr.String()
	br := bufio.NewReaderSize(r, 64<<10)
	lineNo := 0
	for {
		if lineNo%512 == 0 && ctx.Err() != nil {
			ev.Note = "extraction cancelled"
			return
		}
		lineNo++

		line, tooLong, err := readCappedLine(br)
		if line != nil {
			if skipPartial {
				skipPartial = false
			} else if containsIPToken(line, needle, addr.Is4()) {
				if tooLong {
					ev.Truncated = true
				}
				appendEvidenceLine(ev, string(line))
			}
		}
		if err != nil {
			return // io.EOF or read error: either way we report what we got
		}
	}
}

// appendEvidenceLine adds line to ev.Lines, keeping only the most recent
// evidenceMaxLines entries (the oldest is dropped and Truncated is set).
func appendEvidenceLine(ev *sdk.AbuseReportEvidence, line string) {
	ev.Lines = append(ev.Lines, line)
	if len(ev.Lines) > evidenceMaxLines {
		ev.Lines = ev.Lines[1:]
		ev.Truncated = true
	}
}

// readCappedLine reads one line, truncating it at evidenceMaxLineBytes while
// still consuming the remainder so the next read starts at the next line.
// It returns the (possibly truncated) line without the newline, whether it
// was truncated, and the terminal error (io.EOF after the last line).
func readCappedLine(r *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		frag, isPrefix, rerr := r.ReadLine()
		if len(frag) > 0 {
			switch {
			case len(line) >= evidenceMaxLineBytes:
				tooLong = true // discard the rest of an oversized line
			case len(line)+len(frag) > evidenceMaxLineBytes:
				line = append(line, frag[:evidenceMaxLineBytes-len(line)]...)
				tooLong = true
			default:
				line = append(line, frag...)
			}
		}
		if rerr != nil {
			return line, tooLong, rerr
		}
		if !isPrefix {
			return line, tooLong, nil
		}
	}
}

// containsIPToken reports whether line contains needle as a complete
// address token — i.e. not as a substring of a longer address. For IPv4 the
// neighbour bytes must not be digits or '.' (so "1.2.3.4" does not match
// inside "11.2.3.45", but "1.2.3.4:443" does match); for IPv6 they must not
// be hex digits, ':' or '.' (v4-mapped tails).
func containsIPToken(line []byte, needle string, isV4 bool) bool {
	nb := []byte(needle)
	for start := 0; ; {
		idx := bytes.Index(line[start:], nb)
		if idx < 0 {
			return false
		}
		idx += start
		end := idx + len(nb)
		if !isAddrByte(line, idx-1, isV4) && !isAddrByte(line, end, isV4) {
			return true
		}
		start = idx + 1
	}
}

// isAddrByte reports whether the byte at position i of line could belong to
// an address of the given family (out-of-range positions are boundaries).
func isAddrByte(line []byte, i int, isV4 bool) bool {
	if i < 0 || i >= len(line) {
		return false
	}
	b := line[i]
	if b >= '0' && b <= '9' || b == '.' {
		return true
	}
	if isV4 {
		return false
	}
	return b == ':' || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
