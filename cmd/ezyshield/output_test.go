package main

// Tests for the shared color gate (issue #106): --no-color flag, NO_COLOR
// env var, and TTY detection. Not parallel: they mutate the noColor package
// global and the process environment.

import (
	"bytes"
	"os"
	"testing"
)

func TestColorEnabled_NonFileWriterIsPlain(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	noColor = false

	if colorEnabled(&bytes.Buffer{}) {
		t.Error("colorEnabled(bytes.Buffer) = true, want false (not a terminal)")
	}
}

func TestColorEnabled_RegularFileIsPlain(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	noColor = false

	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	if colorEnabled(f) {
		t.Error("colorEnabled(regular file) = true, want false (redirected output)")
	}
}

// TestColorEnabled_CharDevice uses /dev/null — a character device, which is
// what the Stat-mode TTY heuristic keys on — to exercise the "interactive
// terminal" branch deterministically in CI (no PTY needed).
func TestColorEnabled_CharDevice(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	noColor = false

	dev, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	defer dev.Close() //nolint:errcheck

	if !colorEnabled(dev) {
		t.Error("colorEnabled(char device) = false, want true")
	}

	t.Run("NO_COLOR env disables", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		if colorEnabled(dev) {
			t.Error("colorEnabled = true with NO_COLOR set, want false")
		}
	})

	t.Run("--no-color flag disables", func(t *testing.T) {
		noColor = true
		defer func() { noColor = false }()
		if colorEnabled(dev) {
			t.Error("colorEnabled = true with --no-color, want false")
		}
	})
}

// TestNoColorFlagWiring proves the persistent --no-color flag reaches the
// shared gate through a real invocation.
func TestNoColorFlagWiring(t *testing.T) {
	noColor = false
	var out, errOut bytes.Buffer
	if code := runMain([]string{"version", "--no-color"}, &out, &errOut); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, errOut.String())
	}
	if !noColor {
		t.Error("--no-color did not set the noColor gate")
	}
	noColor = false
}
