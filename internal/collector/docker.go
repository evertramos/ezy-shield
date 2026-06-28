//go:build linux

// Package collector provides log collectors that implement sdk.Collector.
package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// reDockerContainerName is an allowlist for Docker container names and IDs.
// Names: [a-zA-Z0-9][a-zA-Z0-9_.-]* Short IDs: 12 hex chars. Full IDs: 64 hex.
// The pattern covers all valid forms.
var reDockerContainerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$`)

const (
	dockerBackoffBase = time.Second
	dockerBackoffMax  = 30 * time.Second
)

// DockerCollector streams a container's logs and emits one RawLine per line.
//
// Primary path (issue #93): the Docker Engine API on a unix socket
// (DockerSocketPath, default "/var/run/docker.sock"). This avoids reading
// /var/lib/docker/containers/<id>/<id>-json.log directly, which requires +x on
// every parent dir and is reset to 0710 by Docker package upgrades.
//
// Fallback: if the socket is unavailable (missing, not a socket, or unreachable),
// the collector resolves the log path via `docker inspect` and tails the file.
// For json-file drivers the Docker JSON wrapper is unwrapped; for journald
// drivers, journalctl is spawned with a CONTAINER_NAME= filter.
//
// The emitted RawLine.Source is "<Parser>:<Container>" when Parser is set,
// or "docker:<Container>" otherwise — so parser routing (Matches) works.
type DockerCollector struct {
	// Container is the container name or short/full ID (required).
	Container string
	// Parser, if set, selects the parser (e.g. "nginx", "ssh").
	// Source becomes "<Parser>:<Container>" which the matching parser's
	// Matches() method accepts via its "<parser>:" prefix check.
	Parser string
	// Logger receives debug/warn messages. If nil, slog.Default() is used.
	Logger *slog.Logger
	// DockerCmd overrides the docker binary path. Empty means "docker".
	// Set in tests to a mock script; never used to pass untrusted input.
	DockerCmd string
	// DockerSocketPath overrides /var/run/docker.sock. Empty means the
	// default. Tests set this to a missing path to force the filesystem
	// fallback without touching the host's real socket.
	DockerSocketPath string
}

// defaultDockerSocketPath is the canonical Docker Engine API endpoint.
const defaultDockerSocketPath = "/var/run/docker.sock"

// Run starts the collector loop. It prefers the Docker Engine API; on
// startup it checks whether the unix socket is reachable and, if so, streams
// logs via GET /containers/<name>/logs (issue #93). When the socket is
// missing or unreachable it falls back to docker inspect + filesystem tail.
// Returns nil on clean shutdown (context cancelled).
func (c *DockerCollector) Run(ctx context.Context, out chan<- sdk.RawLine) error {
	logger := c.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if !reDockerContainerName.MatchString(c.Container) {
		return fmt.Errorf("docker: invalid container name %q (must match [a-zA-Z0-9][a-zA-Z0-9_.-]*)", c.Container)
	}

	source := "docker:" + c.Container
	if c.Parser != "" {
		source = c.Parser + ":" + c.Container
	}

	socketPath := c.DockerSocketPath
	if socketPath == "" {
		socketPath = defaultDockerSocketPath
	}
	if isUnixSocket(socketPath) {
		logger.Info("docker: using Engine API",
			slog.String("container", c.Container),
			slog.String("socket", socketPath),
		)
		return c.runAPI(ctx, socketPath, source, out, logger)
	}
	logger.Warn("docker: engine socket unavailable, falling back to filesystem tail (see issue #93)",
		slog.String("container", c.Container),
		slog.String("socket", socketPath),
	)

	backoff := dockerBackoffBase

	for {
		if ctx.Err() != nil {
			return nil
		}

		logPath, driver, err := c.inspect(ctx)
		if err != nil {
			logger.Warn("docker: inspect failed; waiting for container",
				slog.String("container", c.Container),
				slog.String("err", err.Error()),
				slog.Duration("backoff", backoff),
			)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, dockerBackoffMax)
			continue
		}

		// Successful inspect — reset backoff.
		backoff = dockerBackoffBase

		var tailErr error
		switch driver {
		case "json-file":
			tailErr = c.tailJSONFile(ctx, logPath, source, out, logger)
		case "journald":
			tailErr = c.tailJournald(ctx, source, out, logger)
		default:
			logger.Warn("docker: unknown log driver; trying json-file",
				slog.String("driver", driver),
				slog.String("container", c.Container),
			)
			tailErr = c.tailJSONFile(ctx, logPath, source, out, logger)
		}

		if ctx.Err() != nil {
			return nil
		}

		if tailErr != nil {
			logger.Warn("docker: tail error; re-resolving container",
				slog.String("container", c.Container),
				slog.String("err", tailErr.Error()),
				slog.Duration("backoff", backoff),
			)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, dockerBackoffMax)
	}
}

// dockerBin returns the docker binary path to use.
func (c *DockerCollector) dockerBin() string {
	if c.DockerCmd != "" {
		return c.DockerCmd
	}
	return "docker"
}

// inspect runs docker inspect twice to retrieve logPath and driver separately.
// c.Container is validated before this is called.
func (c *DockerCollector) inspect(ctx context.Context) (logPath, driver string, err error) {
	logPath, err = c.runInspect(ctx, "{{.LogPath}}")
	if err != nil {
		return "", "", err
	}
	driver, err = c.runInspect(ctx, "{{.HostConfig.LogConfig.Type}}")
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(logPath), strings.TrimSpace(driver), nil
}

// runInspect executes docker inspect with the given Go template format string.
// The container name is passed as a separate argument (no shell expansion).
func (c *DockerCollector) runInspect(ctx context.Context, format string) (string, error) {
	//nolint:gosec // c.Container validated against reDockerContainerName; exec.Command not shell
	cmd := exec.CommandContext(ctx, c.dockerBin(), "inspect", "--format", format, c.Container)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker inspect %s: %w", c.Container, err)
	}
	return string(out), nil
}

// dockerJSONEntry is the per-line structure written by Docker's json-file log driver.
type dockerJSONEntry struct {
	Log    string `json:"log"`
	Stream string `json:"stream"`
}

// tailJSONFile starts FileTailCollector on logPath, unwraps Docker JSON wrappers,
// and forwards the inner log lines to out with the correct source.
func (c *DockerCollector) tailJSONFile(ctx context.Context, logPath, source string, out chan<- sdk.RawLine, logger *slog.Logger) error {
	if err := validateDockerLogPath(logPath); err != nil {
		return err
	}

	inner := make(chan sdk.RawLine, 64)

	tailCtx, tailCancel := context.WithCancel(ctx)
	defer tailCancel()

	tail := &FileTailCollector{
		Path:   logPath,
		Logger: logger,
	}

	done := make(chan error, 1)
	go func() {
		done <- tail.Run(tailCtx, inner)
	}()

	for {
		select {
		case rawLine := <-inner:
			line := unwrapDockerJSONLine(rawLine.Line)
			out <- sdk.RawLine{
				Source: source,
				Line:   []byte(strings.TrimRight(line, "\n")),
				At:     rawLine.At,
			}
		case err := <-done:
			// Drain any buffered lines before returning.
			for {
				select {
				case rawLine := <-inner:
					line := unwrapDockerJSONLine(rawLine.Line)
					out <- sdk.RawLine{
						Source: source,
						Line:   []byte(strings.TrimRight(line, "\n")),
						At:     rawLine.At,
					}
				default:
					return err
				}
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// unwrapDockerJSONLine extracts the inner "log" value from a Docker json-file
// log entry. Returns the original bytes (as string) if not a Docker JSON entry.
func unwrapDockerJSONLine(raw []byte) string {
	if len(raw) == 0 || raw[0] != '{' {
		return string(raw)
	}
	var entry dockerJSONEntry
	if err := json.Unmarshal(raw, &entry); err != nil || entry.Log == "" {
		return string(raw)
	}
	return entry.Log
}

// tailJournald spawns journalctl with a CONTAINER_NAME filter to follow
// Docker container logs written to the system journal.
func (c *DockerCollector) tailJournald(ctx context.Context, source string, out chan<- sdk.RawLine, logger *slog.Logger) error {
	// CONTAINER_NAME= is a journald match field — safe with validated container name.
	//nolint:gosec // c.Container validated against reDockerContainerName; exec.Command not shell
	cmd := exec.CommandContext(ctx, "journalctl",
		"-f", "-o", "cat", "--no-pager",
		"CONTAINER_NAME="+c.Container,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("docker journald: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("docker journald: start journalctl: %w", err)
	}

	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Bytes()
		cp := make([]byte, len(line))
		copy(cp, line)
		out <- sdk.RawLine{
			Source: source,
			Line:   cp,
			At:     time.Now(),
		}
	}
	if err := sc.Err(); err != nil {
		logger.Debug("docker journald: scanner error",
			slog.String("err", err.Error()),
			slog.String("container", c.Container),
		)
	}

	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if waitErr != nil {
		return fmt.Errorf("docker journald: journalctl exited: %w", waitErr)
	}
	return nil
}

// validateDockerLogPath rejects empty paths, non-absolute paths, and paths
// containing ".." components to prevent traversal of the container log path
// returned by docker inspect.
func validateDockerLogPath(p string) error {
	if p == "" {
		return fmt.Errorf("docker: inspect returned empty log path")
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("docker: log path is not absolute: %q", redactPath(p))
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return fmt.Errorf("docker: log path contains '..': %q", redactPath(p))
		}
	}
	return nil
}

// redactPath truncates a path at 100 chars to avoid logging unbounded attacker input.
func redactPath(s string) string {
	if len(s) > 100 {
		return s[:100] + "…"
	}
	return s
}

// isUnixSocket reports whether path exists and is a unix socket. Tests on
// hosts that happen to have a real /var/run/docker.sock can override
// DockerCollector.DockerSocketPath to a missing path to bypass the API path.
func isUnixSocket(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSocket != 0
}
