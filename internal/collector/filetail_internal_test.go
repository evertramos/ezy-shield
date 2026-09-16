// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package collector

// Internal tests for the inotify re-watch path (issue #634): they inject a
// failing InotifyAddWatch through the package hook, which the external
// tests cannot reach.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// watchHook returns an addWatch implementation for the collector under
// test: calls whose ordinal (1-based) `fails` returns true fail with EMFILE
// (the "too many watches" shape); the rest go to the kernel. `before`, when
// set, runs ahead of the real call — the reviewer's TOCTOU probe. The
// counter reports the calls made.
func watchHook(fails func(call int64) bool, before func(call int64, path string)) (func(int, string, uint32) (int, error), *atomic.Int64) {
	calls := &atomic.Int64{}
	return func(fd int, path string, mask uint32) (int, error) {
		n := calls.Add(1)
		if fails(n) {
			return -1, unix.EMFILE
		}
		if before != nil {
			before(n, path)
		}
		return unix.InotifyAddWatch(fd, path, mask)
	}, calls
}

func appendInternal(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

// rotateInternal renames the live file away and recreates it (logrotate
// create mode), then waits out the collector's reopen window.
func rotateInternal(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.Rename(path, fmt.Sprintf("%s.%d", path, n)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
}

func collectInternal(out <-chan sdk.RawLine, n int, wait time.Duration) []string {
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
	return got
}

func startInternal(t *testing.T, path string, hook func(int, string, uint32) (int, error)) <-chan sdk.RawLine {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	out := make(chan sdk.RawLine, 64)
	c := &FileTailCollector{Path: path, Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)), addWatch: hook}
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, out) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(150 * time.Millisecond)
	return out
}

// Watch calls through the hook: 1 = file watch at start (the directory
// watch does not go through it), 2 = re-watch after the first rotation,
// 3+ = retries / later rotations.

// TestFileTailCollector_RewatchFailureIsRetried: the re-watch after a
// rotation fails once; the collector must keep delivering and retry the
// watch instead of relying on the stat fallback for good.
func TestFileTailCollector_RewatchFailureIsRetried(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hook, calls := watchHook(func(n int64) bool { return n == 2 }, nil)
	out := startInternal(t, path, hook)

	appendInternal(t, path, "L1")
	rotateInternal(t, path, 1)
	appendInternal(t, path, "L2")
	got := collectInternal(out, 2, 5*time.Second)
	if strings.Join(got, ",") != "L1,L2" {
		t.Fatalf("lines = %v, want [L1 L2]", got)
	}
	// The failed re-watch must have been retried by now (poll timeout 500 ms).
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := calls.Load(); n < 3 {
		t.Fatalf("watch calls = %d, want the failed re-watch to be retried", n)
	}
}

// TestFileTailCollector_RenameFollowedWithoutWatch: every re-watch fails
// (EMFILE stays). Without a watch, fstat on the open descriptor can never
// see a rename, so the second rotation used to leave the collector on a
// dead inode forever — L3 never arrived. The path's inode must be compared
// with the descriptor's on the timeout tick.
func TestFileTailCollector_RenameFollowedWithoutWatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hook, _ := watchHook(func(n int64) bool { return n >= 2 }, nil)
	out := startInternal(t, path, hook)

	appendInternal(t, path, "L1")
	rotateInternal(t, path, 1)
	appendInternal(t, path, "L2")
	rotateInternal(t, path, 2)
	time.Sleep(700 * time.Millisecond) // one full poll timeout with no watch
	appendInternal(t, path, "L3")
	got := collectInternal(out, 3, 6*time.Second)
	if strings.Join(got, ",") != "L1,L2,L3" {
		t.Fatalf("lines = %v, want [L1 L2 L3] — a rename after a failed re-watch was not followed", got)
	}
}

// TestFileTailCollector_RewatchRetryDuringRotation (adversarial review of
// #640): logrotate runs in the instant between the retry tick's inode
// check and its InotifyAddWatch. Checking the inode first installed the
// watch on the NEW file while the descriptor stayed on the rotated one,
// and every later line was lost silently — the retry must come first.
func TestFileTailCollector_RewatchRetryDuringRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hook, calls := watchHook(
		func(n int64) bool { return n == 2 }, // re-watch after rotation 1 fails
		func(n int64, p string) {
			if n == 3 { // the retry tick: rotate right before the kernel call resolves the path
				if err := os.Rename(p, p+".2"); err != nil {
					t.Error(err)
				}
				if err := os.WriteFile(p, nil, 0o600); err != nil {
					t.Error(err)
				}
			}
		})
	out := startInternal(t, path, hook)

	appendInternal(t, path, "L1")
	rotateInternal(t, path, 1)
	time.Sleep(700 * time.Millisecond) // the retry tick has run (and rotated underneath it)
	appendInternal(t, path, "L3")      // lands on the newest inode
	got := collectInternal(out, 2, 5*time.Second)
	if strings.Join(got, ",") != "L1,L3" {
		t.Fatalf("lines = %v (watch calls %d), want [L1 L3]: watch on the new inode, descriptor on the old one", got, calls.Load())
	}
}
