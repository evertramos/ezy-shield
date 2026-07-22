package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFakeBin(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
}

func TestCheckPathShadowing(t *testing.T) {
	t.Parallel()

	t.Run("single PATH location returns N/A", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFakeBin(t, filepath.Join(dir, "ezyshield"), "v1")

		results := checkPathShadowing(dir, []string{"ezyshield"})
		if len(results) != 1 || results[0].Status != statusNA {
			t.Fatalf("got %+v, want single N/A result", results)
		}
	})

	t.Run("two locations identical content returns PASS", func(t *testing.T) {
		t.Parallel()
		dirA, dirB := t.TempDir(), t.TempDir()
		writeFakeBin(t, filepath.Join(dirA, "ezyshield"), "same-bytes")
		writeFakeBin(t, filepath.Join(dirB, "ezyshield"), "same-bytes")

		pathEnv := dirA + string(os.PathListSeparator) + dirB
		results := checkPathShadowing(pathEnv, []string{"ezyshield"})
		if len(results) != 1 || results[0].Status != statusPass {
			t.Fatalf("got %+v, want single PASS result", results)
		}
	})

	t.Run("two locations differing content returns FAIL naming the winner", func(t *testing.T) {
		t.Parallel()
		dirA, dirB := t.TempDir(), t.TempDir()
		writeFakeBin(t, filepath.Join(dirA, "ezyshield"), "old-script-install-bytes")
		writeFakeBin(t, filepath.Join(dirB, "ezyshield"), "new-package-bytes")

		pathEnv := dirA + string(os.PathListSeparator) + dirB
		results := checkPathShadowing(pathEnv, []string{"ezyshield"})
		if len(results) != 1 {
			t.Fatalf("got %d results, want 1", len(results))
		}
		r := results[0]
		if r.Status != statusFail {
			t.Fatalf("got status %s, want %s (hint=%s)", r.Status, statusFail, r.Hint)
		}
		winner := filepath.Join(dirA, "ezyshield")
		if !strings.Contains(r.Hint, winner) {
			t.Errorf("hint does not name the winning (first-in-PATH) path %q: %s", winner, r.Hint)
		}
		if !strings.Contains(r.Hint, "systemctl stop") || !strings.Contains(r.Hint, "rm -f") {
			t.Errorf("hint missing exact cleanup commands: %s", r.Hint)
		}
	})

	t.Run("checks both binary names independently", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFakeBin(t, filepath.Join(dir, "ezyshield"), "v1")

		results := checkPathShadowing(dir, []string{"ezyshield", "ezyshield-enforcer"})
		if len(results) != 2 {
			t.Fatalf("got %d results, want 2 (one per binary)", len(results))
		}
	})

	t.Run("duplicate PATH entries counted once", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFakeBin(t, filepath.Join(dir, "ezyshield"), "v1")

		pathEnv := dir + string(os.PathListSeparator) + dir
		results := checkPathShadowing(pathEnv, []string{"ezyshield"})
		if results[0].Status != statusNA {
			t.Fatalf("got %s, want N/A (same dir listed twice must not look like shadowing)", results[0].Status)
		}
	})
}

func TestCheckUnitShadowing(t *testing.T) {
	t.Parallel()

	t.Run("no package binary present returns N/A even with an override unit", func(t *testing.T) {
		t.Parallel()
		unitDir := t.TempDir()
		binDir := t.TempDir() // no ezyshield binary written here
		writeUnit(t, filepath.Join(unitDir, "ezyshield.service"), "/usr/local/bin/ezyshield")

		results := checkUnitShadowing(unitDir, []string{binDir}, []string{"ezyshield.service"})
		if len(results) != 1 || results[0].Status != statusNA {
			t.Fatalf("got %+v, want N/A", results)
		}
	})

	t.Run("package binary present, no override unit returns N/A", func(t *testing.T) {
		t.Parallel()
		unitDir := t.TempDir()
		binDir := t.TempDir()
		writeFakeBin(t, filepath.Join(binDir, "ezyshield"), "pkg-bytes")

		results := checkUnitShadowing(unitDir, []string{binDir}, []string{"ezyshield.service"})
		if len(results) != 1 || results[0].Status != statusNA {
			t.Fatalf("got %+v, want N/A (no unit file at all)", results)
		}
	})

	t.Run("override unit ExecStart outside package dirs returns FAIL", func(t *testing.T) {
		t.Parallel()
		unitDir := t.TempDir()
		binDir := t.TempDir()
		writeFakeBin(t, filepath.Join(binDir, "ezyshield"), "pkg-bytes")
		writeUnit(t, filepath.Join(unitDir, "ezyshield.service"), "/usr/local/bin/ezyshield")

		results := checkUnitShadowing(unitDir, []string{binDir}, []string{"ezyshield.service"})
		if len(results) != 1 {
			t.Fatalf("got %d results, want 1", len(results))
		}
		r := results[0]
		if r.Status != statusFail {
			t.Fatalf("got status %s, want %s (hint=%s)", r.Status, statusFail, r.Hint)
		}
		if !strings.Contains(r.Hint, "systemctl stop") || !strings.Contains(r.Hint, "rm -f") ||
			!strings.Contains(r.Hint, "daemon-reload") || !strings.Contains(r.Hint, "enable --now") {
			t.Errorf("hint missing exact cleanup commands: %s", r.Hint)
		}
	})

	t.Run("override unit ExecStart already in a package dir returns PASS", func(t *testing.T) {
		t.Parallel()
		unitDir := t.TempDir()
		binDir := t.TempDir()
		writeFakeBin(t, filepath.Join(binDir, "ezyshield"), "pkg-bytes")
		writeUnit(t, filepath.Join(unitDir, "ezyshield.service"), filepath.Join(binDir, "ezyshield"))

		results := checkUnitShadowing(unitDir, []string{binDir}, []string{"ezyshield.service"})
		if len(results) != 1 || results[0].Status != statusPass {
			t.Fatalf("got %+v, want PASS", results)
		}
	})

	t.Run("ExecStart prefix modifiers (-) are stripped before comparison", func(t *testing.T) {
		t.Parallel()
		unitDir := t.TempDir()
		binDir := t.TempDir()
		writeFakeBin(t, filepath.Join(binDir, "ezyshield"), "pkg-bytes")
		writeUnit(t, filepath.Join(unitDir, "ezyshield.service"), "-"+filepath.Join(binDir, "ezyshield"))

		results := checkUnitShadowing(unitDir, []string{binDir}, []string{"ezyshield.service"})
		if len(results) != 1 || results[0].Status != statusPass {
			t.Fatalf("got %+v, want PASS (leading '-' modifier must be stripped)", results)
		}
	})
}

func TestParseExecStart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		unit string
		want string
	}{
		{"simple", "[Service]\nExecStart=/usr/bin/ezyshield run\n", "/usr/bin/ezyshield"},
		{"dash modifier", "[Service]\nExecStart=-/usr/bin/ezyshield\n", "/usr/bin/ezyshield"},
		{"no ExecStart", "[Service]\nType=simple\n", ""},
		{"leading whitespace", "[Service]\n  ExecStart=/usr/local/bin/ezyshield\n", "/usr/local/bin/ezyshield"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := parseExecStart(tc.unit); got != tc.want {
				t.Errorf("parseExecStart(%q) = %q, want %q", tc.unit, got, tc.want)
			}
		})
	}
}

func TestCheckInstallShadowing_NoShadowing(t *testing.T) {
	t.Parallel()
	// A pristine environment (empty PATH search, no real binaries in it)
	// must never crash and must never report FAIL just because nothing is
	// installed at all.
	dir := t.TempDir()
	results := checkInstallShadowing(dir)
	for _, r := range results {
		if r.Status == statusFail {
			t.Errorf("unexpected FAIL on empty environment: %+v", r)
		}
	}
}

// writeUnit writes a minimal systemd unit file with the given ExecStart
// binary path.
func writeUnit(t *testing.T, path, execStartBin string) {
	t.Helper()
	content := "[Service]\nExecStart=" + execStartBin + " run\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
}
