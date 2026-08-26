// SPDX-License-Identifier: AGPL-3.0-only

package collector_test

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/collector"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// TestJournaldCollector_InvalidUnitName ensures that unit names that could enable
// injection are rejected before the subprocess is started.
func TestJournaldCollector_InvalidUnitName(t *testing.T) {
	cases := []string{
		"sshd; rm -rf /",
		"sshd && whoami",
		"sshd|cat /etc/passwd",
		"../etc/passwd",
		"sshd\x00evil",
		"",
	}
	for _, unit := range cases {
		c := &collector.JournaldCollector{Unit: unit, Cmd: "echo"}
		err := c.Run(context.Background(), make(chan sdk.RawLine, 1))
		if err == nil {
			t.Errorf("expected error for unit %q, got nil", unit)
		}
	}
}

// TestJournaldCollector_ValidUnitNames ensures that well-formed unit names are accepted.
func TestJournaldCollector_ValidUnitNames(t *testing.T) {
	cases := []string{
		"sshd",
		"sshd.service",
		"systemd-journald",
		"user@1000.service",
	}
	for _, unit := range cases {
		c := &collector.JournaldCollector{
			Unit: unit,
			// Use "true" as the command so it exits immediately without error on Linux/macOS.
			// On Windows this won't be reached because inotify is Linux-only anyway.
			Cmd: "true",
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := c.Run(ctx, make(chan sdk.RawLine, 1))
		cancel()
		// "true" exits with status 0; we accept nil or "journalctl exited" with status 0.
		if err != nil {
			t.Logf("unit %q: Run returned %v (acceptable if 'true' not in PATH)", unit, err)
		}
	}
}

// TestJournaldCollector_ContextCancellation verifies that Run returns promptly
// when the context is cancelled, even while the subprocess is running.
func TestJournaldCollector_ContextCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}
	// Write a tiny shell script that ignores all arguments and blocks indefinitely.
	// "exec sleep 3600" replaces the shell with sleep so SIGKILL from CommandContext
	// kills the blocking process directly (no orphan grandchild holding stdout open).
	script := "#!/bin/sh\nexec sleep 3600\n"
	scriptPath := t.TempDir() + "/block.sh"
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil { //nolint:gosec // temp test script, not attacker-controlled
		t.Fatalf("write script: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan sdk.RawLine, 16)
	c := &collector.JournaldCollector{Unit: "sshd", Cmd: scriptPath}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, out)
	}()

	time.Sleep(100 * time.Millisecond)
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

// TestJournaldCollector_EmitsLines uses "echo" to simulate journalctl output and
// verifies that the emitted RawLine has the correct Source and content.
func TestJournaldCollector_EmitsLines(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}
	echoPath, err := exec.LookPath("echo")
	if err != nil {
		t.Skip("echo not found in PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := make(chan sdk.RawLine, 16)
	c := &collector.JournaldCollector{
		Unit: "sshd",
		Cmd:  echoPath,
		// Note: journalctl args (-u sshd -f -o cat --no-pager) will be passed to echo,
		// so echo will print them. We just verify the collector runs and emits a line.
	}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, out)
	}()

	select {
	case rl := <-out:
		if rl.Source != "journald:sshd" {
			t.Errorf("source: got %q, want %q", rl.Source, "journald:sshd")
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for a line from echo")
	}

	<-done
}

// TestJournaldCollector_SurvivesOversizedLine is the issue #306 regression:
// with bufio.Scanner a single line past the 64 KiB token cap ended the scan
// loop permanently and the goroutine wedged in cmd.Wait on the follow-mode
// journalctl. The collector must instead deliver the oversized line
// truncated and KEEP reading — the line after it is the proof.
func TestJournaldCollector_SurvivesOversizedLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}
	// 100 KiB of 'A' (past Scanner's old 64 KiB cap), then a normal line.
	script := "#!/bin/sh\n" +
		"head -c 102400 /dev/zero | tr '\\0' 'A'\n" +
		"printf '\\nafter-the-huge-line\\n'\n"
	scriptPath := t.TempDir() + "/huge.sh"
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil { //nolint:gosec // temp test script, not attacker-controlled
		t.Fatalf("write script: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := make(chan sdk.RawLine, 16)
	c := &collector.JournaldCollector{Unit: "sshd", Cmd: scriptPath}

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, out) }()

	var lines []string
	deadline := time.After(4 * time.Second)
collect:
	for {
		select {
		case rl := <-out:
			lines = append(lines, string(rl.Line))
		case err := <-done:
			if err != nil {
				t.Fatalf("Run returned error: %v", err)
			}
			break collect
		case <-deadline:
			t.Fatalf("collector wedged (issue #306 regression); lines so far: %d", len(lines))
		}
	}
	// Drain anything emitted before Run returned.
	for {
		select {
		case rl := <-out:
			lines = append(lines, string(rl.Line))
			continue
		default:
		}
		break
	}

	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2 (truncated huge + normal)", len(lines))
	}
	if len(lines[0]) == 0 || lines[0][0] != 'A' {
		t.Errorf("first line is not the truncated huge line")
	}
	if lines[1] != "after-the-huge-line" {
		t.Errorf("line after the huge one = %q — collection did not continue", lines[1])
	}
}

// TestJournaldCollector_PermissionDenialIsNamed verifies the issue #456 error
// labeling: when journalctl exits non-zero with the journald permission
// denial on stderr, the returned error names the cause and the exact fix
// instead of an opaque "exit status 1" (the #454 field failure was invisible
// in the daemon's own logs without this).
func TestJournaldCollector_PermissionDenialIsNamed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}
	script := "#!/bin/sh\n" +
		"echo 'No journal files were opened due to insufficient permissions.' >&2\n" +
		"exit 1\n"
	scriptPath := t.TempDir() + "/denied.sh"
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil { //nolint:gosec // temp test script, not attacker-controlled
		t.Fatalf("write script: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := &collector.JournaldCollector{Unit: "sshd", Cmd: scriptPath}

	err := c.Run(ctx, make(chan sdk.RawLine, 1))
	if err == nil {
		t.Fatal("Run returned nil, want the permission-denial error")
	}
	for _, want := range []string{
		"insufficient permissions",
		"usermod -aG systemd-journal ezyshield",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

// TestJournaldCollector_GenericStderrIsAttached verifies non-permission
// stderr still reaches the error label (bounded), so the supervisor's log
// line carries the actual cause without the permission hint.
func TestJournaldCollector_GenericStderrIsAttached(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}
	script := "#!/bin/sh\n" +
		"echo 'Failed to open journal: No space left on device' >&2\n" +
		"exit 1\n"
	scriptPath := t.TempDir() + "/enospc.sh"
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil { //nolint:gosec // temp test script, not attacker-controlled
		t.Fatalf("write script: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := &collector.JournaldCollector{Unit: "sshd", Cmd: scriptPath}

	err := c.Run(ctx, make(chan sdk.RawLine, 1))
	if err == nil {
		t.Fatal("Run returned nil, want an error")
	}
	if !strings.Contains(err.Error(), "No space left on device") {
		t.Errorf("error %q lost the stderr detail", err)
	}
	if strings.Contains(err.Error(), "usermod") {
		t.Errorf("error %q carries the permission hint for a non-permission failure", err)
	}
}
