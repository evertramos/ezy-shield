package main

// Tests for the shared color gate (issue #106): --no-color flag, NO_COLOR
// env var, and TTY detection. Not parallel: they mutate the noColor package
// global and the process environment.

import (
	"bytes"
	"os"
	"strings"
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

// TestStylerColorOff proves the plain rendering is byte-stable: same text
// and symbols, zero escape codes. This is the form piped output and golden
// tests see (issue #102).
func TestStylerColorOff(t *testing.T) {
	s := styler{color: false}

	got := map[string]string{
		"header": s.header("Environment"),
		"ok":     s.ok("nftables found"),
		"fail":   s.fail("docker not found"),
		"warn":   s.warn("could not detect public IP"),
		"bold":   s.bold("EzyShield setup"),
		"dim":    s.dim("rule"),
	}
	want := map[string]string{
		"header": "Environment\n" + strings.Repeat("─", headerRuleWidth),
		"ok":     "  ✓ nftables found",
		"fail":   "  ✗ docker not found",
		"warn":   "  ! could not detect public IP",
		"bold":   "EzyShield setup",
		"dim":    "rule",
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s = %q, want %q", name, got[name], w)
		}
	}
	for name, g := range got {
		if strings.Contains(g, "\x1b") {
			t.Errorf("%s contains escape codes with color off: %q", name, g)
		}
	}
}

// TestStylerColorOn asserts the exact SGR bytes so a styling regression
// (missing reset, wrong code) fails loudly.
func TestStylerColorOn(t *testing.T) {
	s := styler{color: true}

	tests := []struct{ name, got, want string }{
		{"ok", s.ok("x"), "  " + sgrGreen + "✓" + sgrReset + " x"},
		{"fail", s.fail("x"), "  " + sgrRed + "✗" + sgrReset + " x"},
		{"warn", s.warn("x"), "  " + sgrYellow + "!" + sgrReset + " x"},
		{"bold", s.bold("x"), sgrBold + "x" + sgrReset},
		{"dim", s.dim("x"), sgrDim + "x" + sgrReset},
		{"header", s.header("T"),
			sgrBold + "T" + sgrReset + "\n" + sgrDim + strings.Repeat("─", headerRuleWidth) + sgrReset},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// TestNewStylerMatchesColorGate ties styler construction to the shared
// color gate: a non-TTY writer must always yield a plain styler.
func TestNewStylerMatchesColorGate(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	noColor = false

	if s := newStyler(&bytes.Buffer{}); s.color {
		t.Error("newStyler(bytes.Buffer).color = true, want false (not a terminal)")
	}
}
