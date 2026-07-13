package daemon

// On-demand evidence extraction for journald and docker log sources
// (issue #126). Unlike file sources, these logs are not readable as plain
// files, so the daemon asks the owning system for a bounded tail and filters
// it in-process with the same matching and caps as evidenceFromFile:
//
//   - journald: exec `journalctl -u <unit> -n <window>` (argv only, no
//     shell; the unit name is allowlist-validated). No `--grep`: filtering
//     in-process avoids depending on journalctl's optional PCRE2 support
//     and keeps the target address out of subprocess arguments.
//   - docker:   GET /containers/<name>/logs?tail=<window> on the Engine
//     unix socket (no follow), demultiplexed with the same bounded frame
//     parser the streaming collector uses.
//
// Both paths degrade to an explanatory note on any failure — evidence can
// never fail or stall the report (bounded by evidenceSourceTimeout).

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strconv"

	"github.com/evertramos/ezy-shield/internal/collector"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// evidenceSourceWindowLines is how many recent entries journald/docker are
// asked for before in-process filtering. It bounds the extraction the same
// way evidenceWindowBytes bounds file scans: a busy log costs the same as a
// quiet one.
const evidenceSourceWindowLines = 20000

// evidenceDockerSocketPath is the canonical Docker Engine API endpoint
// (mirrors the collector's default; the collector config has no socket
// override, so neither does evidence).
const evidenceDockerSocketPath = "/var/run/docker.sock"

// evidenceFromJournald extracts recent journal entries for unit that mention
// addr. bin overrides the journalctl binary (tests only); empty means
// "journalctl" resolved from PATH.
func evidenceFromJournald(ctx context.Context, bin, unit string, addr netip.Addr) sdk.AbuseReportEvidence {
	ev := sdk.AbuseReportEvidence{Source: "journald:" + unit}

	// Defense in depth: config validation already constrains the unit name,
	// but never build argv from an unvalidated string.
	if !collector.ValidUnitName(unit) {
		ev.Note = "invalid unit name; skipped"
		return ev
	}
	if bin == "" {
		bin = "journalctl"
	}

	ctx, cancel := context.WithTimeout(ctx, evidenceSourceTimeout)
	defer cancel()

	// -o short-iso: evidence should show *when*, not just what (the
	// streaming collector uses -o cat because parsers expect bare messages).
	//nolint:gosec // bin is "journalctl" or a test override; unit is allowlist-validated above
	cmd := exec.CommandContext(ctx, bin,
		"-u", unit,
		"-o", "short-iso",
		"--no-pager", "-q",
		"-n", strconv.Itoa(evidenceSourceWindowLines),
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		ev.Note = fmt.Sprintf("journalctl: %v", err)
		return ev
	}
	if err := cmd.Start(); err != nil {
		ev.Note = fmt.Sprintf("journalctl unavailable: %v", err)
		return ev
	}

	scanForAddr(ctx, stdout, addr, false, &ev)
	waitErr := cmd.Wait()

	switch {
	case ev.Note != "": // cancellation note from the scan wins
	case ctx.Err() != nil:
		// The timeout killed journalctl mid-read (blocked reads bypass the
		// scan's periodic ctx check). Keep whatever was extracted.
		ev.Note = "extraction cancelled"
	case waitErr != nil && len(ev.Lines) == 0:
		// stderr is deliberately not captured: exit status is enough and
		// journalctl diagnostics stay out of the report payload.
		ev.Note = fmt.Sprintf("journalctl failed: %v", waitErr)
	case len(ev.Lines) == 0:
		ev.Note = fmt.Sprintf("no entries mentioning this address in the last %d journal entries for this unit", evidenceSourceWindowLines)
	}
	return ev
}

// evidenceFromDocker extracts recent container log lines mentioning addr via
// the Docker Engine API (bounded tail, no follow). socketPath overrides the
// engine socket (tests only); empty means /var/run/docker.sock.
func evidenceFromDocker(ctx context.Context, socketPath, container string, addr netip.Addr) sdk.AbuseReportEvidence {
	ev := sdk.AbuseReportEvidence{Source: "docker:" + container}

	// Defense in depth: the name is embedded in the request path below.
	if !collector.ValidContainerName(container) {
		ev.Note = "invalid container name; skipped"
		return ev
	}
	if socketPath == "" {
		socketPath = evidenceDockerSocketPath
	}

	ctx, cancel := context.WithTimeout(ctx, evidenceSourceTimeout)
	defer cancel()

	client := &http.Client{
		Transport: &http.Transport{
			// Host portion of the URL is ignored — always dial the socket.
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
	defer client.CloseIdleConnections()

	// timestamps=true: evidence should show *when* (the streaming collector
	// omits them because parsers expect bare app lines).
	url := "http://docker/containers/" + container +
		"/logs?stdout=true&stderr=true&timestamps=true&tail=" + strconv.Itoa(evidenceSourceWindowLines)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		ev.Note = fmt.Sprintf("docker api: %v", err)
		return ev
	}
	resp, err := client.Do(req)
	if err != nil {
		ev.Note = "docker engine socket unreachable; cannot extract container logs"
		return ev
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		// Drain a bounded chunk for keep-alive cleanliness; never leak the
		// body into the report (SECURITY-REVIEW.md §1).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusNotFound {
			ev.Note = "container not found (removed or renamed?)"
		} else {
			ev.Note = fmt.Sprintf("docker api: HTTP %s", resp.Status)
		}
		return ev
	}

	// Belt-and-braces byte cap on top of the server-side tail bound.
	body := io.LimitReader(resp.Body, evidenceWindowBytes)
	needle := addr.String()
	demuxErr := collector.DemuxDockerLogStream(ctx, body, func(line []byte) bool {
		tooLong := false
		if len(line) > evidenceMaxLineBytes {
			line = line[:evidenceMaxLineBytes]
			tooLong = true
		}
		if containsIPToken(line, needle, addr.Is4()) {
			if tooLong {
				ev.Truncated = true
			}
			appendEvidenceLine(&ev, string(line))
		}
		return false // never stop early: the newest matches win
	})

	switch {
	case ctx.Err() != nil:
		// Timeout mid-stream. Keep whatever was extracted.
		ev.Note = "extraction cancelled"
	case demuxErr != nil:
		// Keep whatever was extracted before the stream broke. A TTY-mode
		// container (raw, unmultiplexed stream) also lands here.
		ev.Note = fmt.Sprintf("container log stream error: %v", demuxErr)
	case len(ev.Lines) == 0:
		ev.Note = fmt.Sprintf("no lines mentioning this address in the last %d container log lines", evidenceSourceWindowLines)
	}
	return ev
}
