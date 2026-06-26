// Package collector provides log collectors that implement sdk.Collector.
// (build tag is absent so this file compiles on all platforms)
package collector

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// reUnitName is an allowlist for journald unit names.
// Only alphanumeric characters plus [._@:-] are accepted to prevent injection.
var reUnitName = regexp.MustCompile(`^[A-Za-z0-9._@:\-]+$`)

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

// Run starts reading log lines from the journald unit and writes them to out
// until ctx is cancelled or the subprocess exits with an error.
// Returns nil on clean shutdown (context cancelled), or a wrapped error.
func (c *JournaldCollector) Run(ctx context.Context, out chan<- sdk.RawLine) error {
	logger := c.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Validate unit name against allowlist to prevent shell injection.
	if !reUnitName.MatchString(c.Unit) {
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

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journald: start journalctl: %w", err)
	}

	source := "journald:" + c.Unit
	sc := bufio.NewScanner(stdout)

	for sc.Scan() {
		line := sc.Bytes()
		// Copy the bytes because the scanner reuses its buffer.
		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)

		out <- sdk.RawLine{
			Source: source,
			Line:   lineCopy,
			At:     time.Now(),
		}
	}

	// sc.Err() is nil if context was cancelled (process was killed by CommandContext).
	if err := sc.Err(); err != nil {
		logger.Debug("journald: scanner error", slog.String("err", err.Error()), slog.String("unit", c.Unit))
	}

	waitErr := cmd.Wait()

	// On context cancellation, exec.CommandContext sends SIGKILL; the resulting
	// "signal: killed" error is expected — return nil.
	if ctx.Err() != nil {
		return nil
	}
	if waitErr != nil {
		return fmt.Errorf("journald: journalctl exited: %w", waitErr)
	}
	return nil
}
