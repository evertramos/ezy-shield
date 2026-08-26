// SPDX-License-Identifier: AGPL-3.0-only

// Package collector provides log collectors that implement sdk.Collector.
// (build tag is absent so this file compiles on all platforms)
package collector

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// JournaldCollector reads log entries for a systemd unit via journalctl.
// It executes journalctl as a subprocess (no CGO, no CGO dependency on libsystemd).
type JournaldCollector struct {
	// Unit is the systemd unit name, e.g. "sshd" or "sshd.service".
	Unit string
	// Logger receives debug/warn messages. If nil, slog.Default() is used.
	Logger *slog.Logger
	// Cmd overrides the journalctl binary path. Empty means "journalctl".
	Cmd string
}

// Name returns a stable identity for supervision logs/alerts (issue #305).
func (c *JournaldCollector) Name() string { return "journald:" + c.Unit }

// Run starts reading log lines from the journald unit and writes them to out
// until ctx is cancelled or the subprocess exits with an error.
// Returns nil on clean shutdown (context cancelled), or a wrapped error.
func (c *JournaldCollector) Run(ctx context.Context, out chan<- sdk.RawLine) error {
	logger := c.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Validate unit name against allowlist to prevent shell injection.
	if !ValidUnitName(c.Unit) {
		return fmt.Errorf("journald: invalid unit name %q (must match [A-Za-z0-9._@:-]+)", c.Unit)
	}

	bin := c.Cmd
	if bin == "" {
		bin = "journalctl"
	}

	// Build command; args are validated — no shell expansion.
	//nolint:gosec // bin is either the default "journalctl" or a test override; Unit is validated above.
	cmd := exec.CommandContext(ctx, bin, "-u", c.Unit, "-f", "-o", "cat", "--no-pager")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journald: stdout pipe: %w", err)
	}
	// Capture (bounded) stderr: journalctl exits 1 both for "cannot read"
	// and for transient conditions, and without its stderr the supervisor
	// could only report an opaque "exit status 1" (issue #456; the field
	// case #454 was a permission denial invisible in the daemon's own logs).
	var stderr boundedBuffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journald: start journalctl: %w", err)
	}

	source := "journald:" + c.Unit
	// forEachLine (not bufio.Scanner) so a hostile oversized line is
	// truncated and drained instead of permanently ending collection
	// (issue #306): Scanner stops at its token cap, and with journalctl -f
	// still running the goroutine then wedged forever in cmd.Wait.
	readErr := forEachLine(stdout, maxStreamLineBytes, func(line []byte, truncated bool) {
		if truncated {
			// Content is untrusted — log only the fact and the cap, never
			// the line itself.
			logger.Warn("journald: oversized log line truncated",
				slog.Int("cap_bytes", maxStreamLineBytes), slog.String("unit", c.Unit))
		}
		// Copy the bytes because the reader reuses its buffer.
		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)

		// Send races cancellation (issue #358): blocking here would wedge
		// the goroutine forever once the pipeline stops reading. The
		// non-blocking attempt runs FIRST so a graceful SIGTERM drain
		// (ctx already done, pipeline still consuming) never randomly
		// drops deliverable lines to the select's uniform choice; only a
		// truly full channel with a dead consumer drops the line.
		rl := sdk.RawLine{Source: source, Line: lineCopy, At: time.Now()}
		select {
		case out <- rl:
		default:
			select {
			case out <- rl:
			case <-ctx.Done():
			}
		}
	})
	if readErr != nil && ctx.Err() == nil {
		logger.Warn("journald: read error", slog.String("err", readErr.Error()), slog.String("unit", c.Unit))
		// A read error while the follow-mode journalctl is still running
		// would leave Wait blocking forever (the second half of issue
		// #306) — kill it so Wait returns and the supervisor can restart us.
		_ = cmd.Process.Kill()
	}

	waitErr := cmd.Wait()

	// On context cancellation, exec.CommandContext sends SIGKILL; the resulting
	// "signal: killed" error is expected — return nil.
	if ctx.Err() != nil {
		return nil
	}
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return fmt.Errorf("journald: journalctl exited: %w", waitErr)
		}
		// Permission denials are the one failure that never self-heals and
		// has a precise fix — name it instead of an opaque exit status
		// (issues #454/#456). Matching on journalctl's message is
		// best-effort: an unmatched denial still surfaces the raw stderr.
		if strings.Contains(msg, "insufficient permissions") {
			return fmt.Errorf(
				"journald: journalctl exited: %w: %s — the service user cannot read the journal; "+
					"fix: usermod -aG systemd-journal ezyshield, then restart ezyshield", waitErr, msg)
		}
		return fmt.Errorf("journald: journalctl exited: %w: %s", waitErr, msg)
	}
	return nil
}

// boundedBuffer keeps the first stderrCap bytes written and drops the rest —
// journalctl stderr is only used to label a failure, and an unbounded buffer
// on a looping subprocess would be a memory leak.
type boundedBuffer struct {
	buf bytes.Buffer
}

// stderrCap bounds how much subprocess stderr is retained for error labels.
const stderrCap = 2048

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if remaining := stderrCap - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			b.buf.Write(p[:remaining])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil // always report full write — dropping is deliberate
}

func (b *boundedBuffer) String() string { return b.buf.String() }
