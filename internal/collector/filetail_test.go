//go:build linux

package collector_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/collector"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// testLogger returns a logger that writes to the test log.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestFileTailCollector_NoPreexistingContent verifies that the collector does NOT
// emit lines that were already in the file before Run was called (tail -f semantics).
func TestFileTailCollector_NoPreexistingContent(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "auth*.log")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	// Write existing content before the collector starts.
	if _, err := f.WriteString("existing line\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	out := make(chan sdk.RawLine, 16)
	c := &collector.FileTailCollector{Path: f.Name(), Logger: testLogger(t)}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, out)
	}()

	<-ctx.Done()
	err = <-done
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	close(out)
	var lines []string
	for rl := range out {
		lines = append(lines, string(rl.Line))
	}
	// Existing content must NOT appear.
	for _, l := range lines {
		if l == "existing line" {
			t.Errorf("pre-existing content was emitted: %q", l)
		}
	}
}

// TestFileTailCollector_EmitsNewLines verifies that lines written after startup are emitted.
func TestFileTailCollector_EmitsNewLines(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "auth*.log")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := make(chan sdk.RawLine, 16)
	c := &collector.FileTailCollector{Path: f.Name(), Logger: testLogger(t)}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, out)
	}()

	// Give the collector a moment to open and seek to end.
	time.Sleep(100 * time.Millisecond)

	// Write a new line.
	const want = "new line after start"
	if _, err := f.WriteString(want + "\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Wait for it to appear on the channel (or timeout).
	select {
	case rl := <-out:
		got := string(rl.Line)
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
		// Verify Source is set correctly.
		if rl.Source != "file:"+c.Path {
			t.Errorf("source: got %q, want %q", rl.Source, "file:"+c.Path)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for new line to appear")
	}

	cancel()
	<-done
}

// TestFileTailCollector_ContextCancellation verifies that Run returns when ctx is cancelled.
func TestFileTailCollector_ContextCancellation(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "auth*.log")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	out := make(chan sdk.RawLine, 16)
	c := &collector.FileTailCollector{Path: f.Name(), Logger: testLogger(t)}

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
	case <-time.After(2 * time.Second):
		t.Error("Run did not return after context cancellation")
	}
}

// TestFileTailCollector_MissingFile verifies that Run returns an error when the
// file does not exist at startup.
func TestFileTailCollector_MissingFile(t *testing.T) {
	ctx := context.Background()
	out := make(chan sdk.RawLine, 1)
	c := &collector.FileTailCollector{
		Path:   "/tmp/ezyshield-nonexistent-test-file-abc123.log",
		Logger: testLogger(t),
	}
	err := c.Run(ctx, out)
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// TestFileTailCollector_CopytruncateRotation verifies that lines written after
// a copytruncate-style in-place truncation are not missed by the stat fallback.
// This guards against the bug where fi.Size() < lastSize left lastSize stale,
// causing all new lines to be invisible until the file grew past the old size.
func TestFileTailCollector_CopytruncateRotation(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "tail_trunc_*.log")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	out := make(chan sdk.RawLine, 32)
	c := &collector.FileTailCollector{Path: f.Name(), Logger: testLogger(t)}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, out)
	}()

	// Let collector open and seek to EOF.
	time.Sleep(150 * time.Millisecond)

	// Write initial content so lastSize is non-zero inside the collector.
	if _, werr := f.WriteString("before-rotation\n"); werr != nil {
		t.Fatalf("write before rotation: %v", werr)
	}

	// Drain the initial line so the channel does not fill up.
	select {
	case <-out:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for pre-rotation line")
	}

	// Simulate copytruncate: truncate the file in-place to 0 bytes.
	// Our file descriptor (inside the collector) still points to the same
	// inode; the collector's stat fallback must detect fi.Size() < lastSize.
	if terr := os.Truncate(f.Name(), 0); terr != nil {
		t.Fatalf("truncate: %v", terr)
	}

	// Give the truncation a moment to be visible via Stat, then write post-rotation lines.
	time.Sleep(150 * time.Millisecond)

	postLines := []string{"after-rotation-1", "after-rotation-2"}
	for _, l := range postLines {
		if _, werr := f.WriteString(l + "\n"); werr != nil {
			t.Fatalf("write after rotation: %v", werr)
		}
	}

	// All post-rotation lines must arrive within the deadline.
	got := make([]string, 0, len(postLines))
	timeout := time.After(5 * time.Second)
	for len(got) < len(postLines) {
		select {
		case rl := <-out:
			got = append(got, string(rl.Line))
		case <-timeout:
			t.Fatalf("timeout: only received %d/%d post-rotation lines: %v", len(got), len(postLines), got)
		}
	}

	for i, want := range postLines {
		if got[i] != want {
			t.Errorf("line[%d]: got %q, want %q", i, got[i], want)
		}
	}

	cancel()
	if err := f.Close(); err != nil {
		t.Logf("close: %v", err)
	}
	<-done
}

// TestFileTailCollector_StatFallbackPolling verifies that lines appended after
// startup are picked up within one poll interval (500 ms) even when inotify
// events are not delivered to Poll — the scenario reported on Debian 12 amd64
// with overlay2.  The test exercises whichever code path fires first (inotify
// or stat-based fallback) and therefore acts as a regression guard for both.
func TestFileTailCollector_StatFallbackPolling(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "tail_stat_*.log")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out := make(chan sdk.RawLine, 32)
	c := &collector.FileTailCollector{Path: f.Name(), Logger: testLogger(t)}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, out)
	}()

	// Wait for the collector to open and seek to end.
	time.Sleep(150 * time.Millisecond)

	// Append three lines in sequence to simulate a growing log file.
	lines := []string{"alpha", "beta", "gamma"}
	for _, l := range lines {
		if _, werr := f.WriteString(l + "\n"); werr != nil {
			t.Fatalf("write: %v", werr)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Collect up to len(lines) entries; each must arrive within the deadline.
	// The stat-based fallback fires at most one pollTimeout (500 ms) after the
	// write, so 3 s total is generous even on a loaded CI runner.
	got := make([]string, 0, len(lines))
	timeout := time.After(3 * time.Second)
	for len(got) < len(lines) {
		select {
		case rl := <-out:
			got = append(got, string(rl.Line))
		case <-timeout:
			t.Fatalf("timeout: only received %d/%d lines: %v", len(got), len(lines), got)
		}
	}

	for i, want := range lines {
		if got[i] != want {
			t.Errorf("line[%d]: got %q, want %q", i, got[i], want)
		}
	}

	cancel()
	<-done
}
