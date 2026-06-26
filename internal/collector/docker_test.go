//go:build linux

package collector_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/collector"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// writeMockDockerScript writes a shell script that acts as a docker binary for tests.
// The script outputs mockLogPath when called with --format {{.LogPath}},
// and mockDriver when called with --format {{.HostConfig.LogConfig.Type}}.
// If the container arg does not match wantContainer, it exits with code 1 (not found).
func writeMockDockerScript(t *testing.T, wantContainer, mockLogPath, mockDriver string) string {
	t.Helper()
	// $4 = container arg (after: docker inspect --format <fmt> <container>)
	script := `#!/bin/sh
set -e
container="$4"
fmt="$3"
if [ "$container" != "` + wantContainer + `" ]; then
  echo "Error: No such container: $container" >&2
  exit 1
fi
case "$fmt" in
  "{{.LogPath}}")
    echo "` + mockLogPath + `"
    ;;
  "{{.HostConfig.LogConfig.Type}}")
    echo "` + mockDriver + `"
    ;;
  *)
    exit 1
    ;;
esac
`
	path := t.TempDir() + "/docker"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil { //nolint:gosec // temp test script
		t.Fatalf("write mock docker script: %v", err)
	}
	return path
}

// writeAlwaysFailScript writes a script that always exits with code 1.
func writeAlwaysFailScript(t *testing.T) string {
	t.Helper()
	script := "#!/bin/sh\necho 'Error: No such container' >&2\nexit 1\n"
	path := t.TempDir() + "/docker"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil { //nolint:gosec // temp test script
		t.Fatalf("write fail script: %v", err)
	}
	return path
}

// TestDockerCollector_InvalidContainerName ensures that container names that could
// enable injection are rejected before any subprocess is started.
func TestDockerCollector_InvalidContainerName(t *testing.T) {
	cases := []string{
		"",
		"my container",        // space
		"container; rm -rf /", // shell metachar
		"../etc/passwd",       // path traversal
		"container\x00evil",   // null byte
		"container|cat",       // pipe
		"container&&whoami",   // double ampersand
	}
	for _, name := range cases {
		c := &collector.DockerCollector{Container: name, DockerCmd: "true"}
		err := c.Run(context.Background(), make(chan sdk.RawLine, 1))
		if err == nil {
			t.Errorf("expected error for container name %q, got nil", name)
		}
	}
}

// TestDockerCollector_ValidContainerNames verifies that well-formed names pass
// validation (no error from the name check itself). We use a short context so
// the inspect-retry loop exits quickly without burning wall-clock time.
func TestDockerCollector_ValidContainerNames(t *testing.T) {
	failScript := writeAlwaysFailScript(t)
	cases := []string{
		"proxy-web",
		"my_container",
		"nginx.1",
		"abc123",
		"a",
		"container-v2.0",
	}
	for _, name := range cases {
		c := &collector.DockerCollector{
			Container: name,
			DockerCmd: failScript,
		}
		// 200 ms is enough: inspect fails instantly, backoff sleep of 1s is
		// cancelled by context timeout, Run returns nil (not an error).
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		err := c.Run(ctx, make(chan sdk.RawLine, 1))
		cancel()
		// nil = context cancelled cleanly; any non-nil means a panic/bug.
		if err != nil {
			t.Errorf("container %q: Run returned unexpected error: %v", name, err)
		}
	}
}

// TestDockerCollector_ContainerNotFound verifies that a missing container logs
// WARN and retries (does not crash). The context timeout ends the loop.
func TestDockerCollector_ContainerNotFound(t *testing.T) {
	failScript := writeAlwaysFailScript(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	c := &collector.DockerCollector{
		Container: "missing-container",
		DockerCmd: failScript,
		Logger:    testLogger(t),
	}
	out := make(chan sdk.RawLine, 8)
	err := c.Run(ctx, out)
	if err != nil {
		t.Errorf("Run returned error (expected nil on context cancel): %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no lines emitted for missing container, got %d", len(out))
	}
}

// TestDockerCollector_JsonFileDriver verifies that Docker JSON wrappers are unwrapped
// and the inner log lines are forwarded with the correct source.
func TestDockerCollector_JsonFileDriver(t *testing.T) {
	// Create a temp log file with Docker JSON-wrapped nginx lines.
	logFile, err := os.CreateTemp(t.TempDir(), "container*.log")
	if err != nil {
		t.Fatalf("create temp log: %v", err)
	}
	defer func() { _ = os.Remove(logFile.Name()) }()

	mockDockerBin := writeMockDockerScript(t, "proxy-web", logFile.Name(), "json-file")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := make(chan sdk.RawLine, 16)
	c := &collector.DockerCollector{
		Container: "proxy-web",
		Parser:    "nginx",
		DockerCmd: mockDockerBin,
		Logger:    testLogger(t),
	}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, out)
	}()

	// Give the collector time to open and seek to end.
	time.Sleep(150 * time.Millisecond)

	// Write a Docker JSON-wrapped nginx access log line.
	// Use json.Marshal so inner quote characters are properly escaped.
	const innerLine = `192.0.2.1 - - [15/Jan/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 1234 "-" "curl"`
	dockerEntry := struct {
		Log    string `json:"log"`
		Stream string `json:"stream"`
		Time   string `json:"time"`
	}{Log: innerLine + "\n", Stream: "stdout", Time: "2025-01-15T10:00:01Z"}
	dockerJSON, err := json.Marshal(dockerEntry)
	if err != nil {
		t.Fatalf("marshal docker entry: %v", err)
	}
	if _, err := logFile.WriteString(string(dockerJSON) + "\n"); err != nil {
		t.Fatalf("write docker log line: %v", err)
	}

	// Also write a plain (non-Docker-JSON) line to ensure pass-through works.
	plainLine := `198.51.100.9 - - [15/Jan/2025:10:00:02 +0000] "GET /.env HTTP/1.1" 404 0 "-" "scanner"`
	if _, err := logFile.WriteString(plainLine + "\n"); err != nil {
		t.Fatalf("write plain line: %v", err)
	}

	// Collect the two emitted lines.
	var received []sdk.RawLine
	timeout := time.After(2 * time.Second)
collect:
	for len(received) < 2 {
		select {
		case rl := <-out:
			received = append(received, rl)
		case <-timeout:
			t.Errorf("timeout: only received %d of 2 expected lines", len(received))
			break collect
		}
	}

	cancel()
	<-done

	if len(received) < 1 {
		t.Fatal("no lines received")
	}

	// First line must be the inner (unwrapped) content.
	if string(received[0].Line) != innerLine {
		t.Errorf("line[0]: got %q, want %q", string(received[0].Line), innerLine)
	}
	// Source must use the parser prefix.
	wantSource := "nginx:proxy-web"
	if received[0].Source != wantSource {
		t.Errorf("source: got %q, want %q", received[0].Source, wantSource)
	}

	if len(received) >= 2 {
		if string(received[1].Line) != plainLine {
			t.Errorf("line[1]: got %q, want %q", string(received[1].Line), plainLine)
		}
	}
}

// TestDockerCollector_SourceDefaultsToDockerPrefix verifies that when no Parser
// is set, source is "docker:<container>".
func TestDockerCollector_SourceDefaultsToDockerPrefix(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "container*.log")
	if err != nil {
		t.Fatalf("create temp log: %v", err)
	}
	defer func() { _ = os.Remove(logFile.Name()) }()

	mockDockerBin := writeMockDockerScript(t, "myapp", logFile.Name(), "json-file")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := make(chan sdk.RawLine, 8)
	c := &collector.DockerCollector{
		Container: "myapp",
		DockerCmd: mockDockerBin,
		Logger:    testLogger(t),
	}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, out)
	}()

	time.Sleep(150 * time.Millisecond)

	// Write a plain line.
	if _, err := logFile.WriteString("hello world\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case rl := <-out:
		if rl.Source != "docker:myapp" {
			t.Errorf("source: got %q, want %q", rl.Source, "docker:myapp")
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for line")
	}

	cancel()
	<-done
}

// TestDockerCollector_ContextCancellation verifies that Run returns nil
// promptly when the context is cancelled (container in json-file mode).
func TestDockerCollector_ContextCancellation(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "container*.log")
	if err != nil {
		t.Fatalf("create temp log: %v", err)
	}
	defer func() { _ = os.Remove(logFile.Name()) }()

	mockDockerBin := writeMockDockerScript(t, "myapp", logFile.Name(), "json-file")

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan sdk.RawLine, 8)
	c := &collector.DockerCollector{
		Container: "myapp",
		DockerCmd: mockDockerBin,
		Logger:    testLogger(t),
	}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, out)
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error on cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Run did not return after context cancellation")
	}
}
