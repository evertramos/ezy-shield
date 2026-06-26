package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// silentCmd returns a cobra.Command whose output is discarded.
func silentCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	return cmd
}

func TestCheckFileExists(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	t.Run("missing file returns FAIL", func(t *testing.T) {
		t.Parallel()
		r := checkFileExists(filepath.Join(dir, "absent.yaml"), "absent")
		if r.Status != statusFail {
			t.Errorf("got status %s, want %s", r.Status, statusFail)
		}
	})

	t.Run("existing regular file returns PASS", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "present.yaml")
		//nolint:gosec // test file, intentional permission
		if err := os.WriteFile(path, []byte("key: val\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		r := checkFileExists(path, "present")
		if r.Status != statusPass {
			t.Errorf("got status %s, want %s", r.Status, statusPass)
		}
	})

	t.Run("directory at path returns FAIL", func(t *testing.T) {
		t.Parallel()
		sub := filepath.Join(dir, "subdir_exists")
		if err := os.Mkdir(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		r := checkFileExists(sub, "subdir")
		if r.Status != statusFail {
			t.Errorf("got status %s, want %s", r.Status, statusFail)
		}
	})
}

func TestCheckFileParses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	t.Run("absent file returns N/A", func(t *testing.T) {
		t.Parallel()
		r := checkFileParses(filepath.Join(dir, "nope.yaml"), "nope")
		if r.Status != statusNA {
			t.Errorf("got status %s, want %s", r.Status, statusNA)
		}
	})

	t.Run("valid YAML returns PASS", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "good.yaml")
		//nolint:gosec // test file, intentional permission
		if err := os.WriteFile(path, []byte("armed: false\nban_threshold: 70\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		r := checkFileParses(path, "good")
		if r.Status != statusPass {
			t.Errorf("got status %s, want %s (hint: %s)", r.Status, statusPass, r.Hint)
		}
	})

	t.Run("invalid YAML returns FAIL", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "bad.yaml")
		//nolint:gosec // test file, intentional permission
		if err := os.WriteFile(path, []byte("key: [\nbad yaml\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		r := checkFileParses(path, "bad")
		if r.Status != statusFail {
			t.Errorf("got status %s, want %s", r.Status, statusFail)
		}
	})
}

func TestCheckFilePerms(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	t.Run("absent file returns N/A", func(t *testing.T) {
		t.Parallel()
		r := checkFilePerms(filepath.Join(dir, "missing.yaml"), "missing")
		if r.Status != statusNA {
			t.Errorf("got status %s, want %s", r.Status, statusNA)
		}
	})

	t.Run("0640 returns PASS", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "ok640.yaml")
		//nolint:gosec // test file, intentional 0640 permission
		if err := os.WriteFile(path, []byte("armed: false\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		r := checkFilePerms(path, "ok640")
		if r.Status != statusPass {
			t.Errorf("got status %s, want %s (hint: %s)", r.Status, statusPass, r.Hint)
		}
	})

	t.Run("0600 returns PASS", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "ok600.yaml")
		if err := os.WriteFile(path, []byte("armed: false\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r := checkFilePerms(path, "ok600")
		if r.Status != statusPass {
			t.Errorf("got status %s, want %s", r.Status, statusPass)
		}
	})

	t.Run("0644 (world-readable) returns FAIL", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "worldread.yaml")
		//nolint:gosec // test file, intentionally insecure permission to verify FAIL
		if err := os.WriteFile(path, []byte("armed: false\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		r := checkFilePerms(path, "worldread")
		if r.Status != statusFail {
			t.Errorf("got status %s, want %s", r.Status, statusFail)
		}
	})

	t.Run("0666 (world-writable) returns FAIL", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "worldwrite.yaml")
		//nolint:gosec // test file, intentionally insecure permission to verify FAIL
		if err := os.WriteFile(path, []byte("armed: false\n"), 0o666); err != nil {
			t.Fatal(err)
		}
		r := checkFilePerms(path, "worldwrite")
		if r.Status != statusFail {
			t.Errorf("got status %s, want %s", r.Status, statusFail)
		}
	})
}

func TestRunDoctor_WithTempDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Both files absent -- doctor must complete without error; file checks return FAIL/N/A.
	if err := runDoctor(silentCmd(), dir, false); err != nil {
		t.Fatalf("runDoctor returned unexpected error: %v", err)
	}
}

func TestRunDoctor_WithValidFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	for _, name := range []string{"config.yaml", "policy.yaml"} {
		path := filepath.Join(dir, name)
		//nolint:gosec // test file, intentional 0640 permission
		if err := os.WriteFile(path, []byte("armed: false\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}

	if err := runDoctor(silentCmd(), dir, false); err != nil {
		t.Fatalf("runDoctor returned unexpected error: %v", err)
	}
}

func TestRunDoctor_JSONOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	buf := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetErr(&bytes.Buffer{})

	if err := runDoctor(cmd, dir, true); err != nil {
		t.Fatalf("runDoctor JSON returned error: %v", err)
	}

	got := buf.String()
	if len(got) == 0 {
		t.Error("expected JSON output, got empty string")
	}
	// Minimal check: JSON output starts with '{'.
	if got[0] != '{' {
		t.Errorf("expected JSON object, got: %.40s", got)
	}
}
