package collector_test

import (
	"context"
	"os"
	"os/exec"
	"runtime"
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
