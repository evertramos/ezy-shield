// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package collector_test

// Regression tests for issue #611 (invariant C1: one log line is counted
// exactly once), on the REAL FileTailCollector over a temp directory.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/collector"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// appendLine writes one line the way rsyslog/nginx do: a fresh O_APPEND open
// per write, so the writer's offset never masks a truncation.
func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // test temp file
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// collect drains out until it has n lines or the deadline passes, then
// waits a little longer to catch any replayed extras.
func collect(t *testing.T, out <-chan sdk.RawLine, n int, wait time.Duration) []string {
	t.Helper()
	var got []string
	deadline := time.After(wait)
	for len(got) < n {
		select {
		case rl := <-out:
			got = append(got, string(rl.Line))
		case <-deadline:
			return got
		}
	}
	// Anything arriving now is a replay or a fragment: the bug signature.
	extra := time.After(800 * time.Millisecond)
	for {
		select {
		case rl := <-out:
			got = append(got, string(rl.Line))
		case <-extra:
			return got
		}
	}
}

func startTail(t *testing.T, path string) (<-chan sdk.RawLine, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	out := make(chan sdk.RawLine, 64)
	c := &collector.FileTailCollector{Path: path, Logger: testLogger(t)}
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, out) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(150 * time.Millisecond) // open + seek to EOF
	return out, cancel
}

// TestFileTailCollector_RenameRotationThenDeleteDoesNotReplay: logrotate
// renames the file and creates a new one; later (compress, or Docker's
// max-file pruning) the rotated file is deleted. Every line must arrive
// exactly once. On dev the deletion fired IN_DELETE_SELF on the stale
// watch of the OLD inode, the collector reopened the CURRENT file at
// offset 0 and re-sent L2 and L3.
func TestFileTailCollector_RenameRotationThenDeleteDoesNotReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := startTail(t, path)

	appendLine(t, path, "L1")
	// Rotation: rename + create.
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // reopen retry window
	appendLine(t, path, "L2")
	appendLine(t, path, "L3")
	time.Sleep(200 * time.Millisecond)
	// The rotated file goes away (logrotate compress / docker max-file).
	if err := os.Remove(rotated); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	appendLine(t, path, "L4")

	got := collect(t, out, 4, 5*time.Second)
	if strings.Join(got, ",") != "L1,L2,L3,L4" {
		t.Fatalf("lines = %v, want exactly [L1 L2 L3 L4] — a replay after the rotated file was deleted", got)
	}
}

// TestFileTailCollector_CopytruncateWithAppendWriter: logrotate copytruncate
// on a file whose writer opens with O_APPEND (rsyslog, nginx). After the
// truncation every new line must arrive once and whole. On dev the
// truncation's IN_MODIFY hit the inotify branch first, which drained at the
// stale offset and reset lastSize to 0, so the stat fallback could never
// notice; reads resumed only once the file grew past the old offset, losing
// A1..A3 and emitting a mid-line fragment.
func TestFileTailCollector_CopytruncateWithAppendWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := startTail(t, path)

	appendLine(t, path, "before-1 "+strings.Repeat("x", 200))
	appendLine(t, path, "before-2 "+strings.Repeat("y", 200))
	if got := collect(t, out, 2, 3*time.Second); len(got) != 2 {
		t.Fatalf("pre-truncate lines = %v, want 2", got)
	}

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	for _, l := range []string{"A1", "A2", "A3", "A4"} {
		appendLine(t, path, l)
		time.Sleep(50 * time.Millisecond)
	}

	got := collect(t, out, 4, 5*time.Second)
	if strings.Join(got, ",") != "A1,A2,A3,A4" {
		t.Fatalf("post-truncate lines = %v, want exactly [A1 A2 A3 A4] (no loss, no fragment)", got)
	}
}
