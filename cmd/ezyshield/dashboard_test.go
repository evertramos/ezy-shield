package main

// Tests for issue #89: the first-run dashboard admin password must never be
// captured by journald / docker logs — when stderr is not a TTY it goes to a
// 0600 file and only the path is printed.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWritePasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard.first-run-password")

	if err := writePasswordFile(path, "s3cret-pw"); err != nil {
		t.Fatalf("writePasswordFile: %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "s3cret-pw\n" {
		t.Errorf("content = %q, want password + newline", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 0600", perm)
	}

	// O_EXCL: a still-unread password from a previous run is never clobbered.
	if err := writePasswordFile(path, "other"); err == nil {
		t.Error("second write should fail on existing file (O_EXCL)")
	}
	got, _ = os.ReadFile(path) //nolint:gosec // test-owned temp path
	if string(got) != "s3cret-pw\n" {
		t.Errorf("existing password was clobbered: %q", got)
	}
}

func TestEmitBootstrapCredentials(t *testing.T) {
	const pw = "correct-horse-battery-staple"

	t.Run("tty prints inline, writes no file", func(t *testing.T) {
		dir := t.TempDir()
		authDB := filepath.Join(dir, "dashboard.db")
		var buf bytes.Buffer

		if err := emitBootstrapCredentials(&buf, true, pw, authDB); err != nil {
			t.Fatalf("emitBootstrapCredentials: %v", err)
		}
		if !strings.Contains(buf.String(), pw) {
			t.Error("TTY branch must print the password inline (no regression)")
		}
		if _, err := os.Stat(filepath.Join(dir, "dashboard.first-run-password")); !os.IsNotExist(err) {
			t.Error("TTY branch must not create a password file")
		}
	})

	t.Run("non-tty writes 0600 file, output has path but no secret", func(t *testing.T) {
		dir := t.TempDir()
		authDB := filepath.Join(dir, "dashboard.db")
		pwPath := filepath.Join(dir, "dashboard.first-run-password")
		var buf bytes.Buffer

		if err := emitBootstrapCredentials(&buf, false, pw, authDB); err != nil {
			t.Fatalf("emitBootstrapCredentials: %v", err)
		}
		out := buf.String()
		if strings.Contains(out, pw) {
			t.Error("non-TTY output must not contain the password (it would land in journald)")
		}
		if !strings.Contains(out, pwPath) {
			t.Errorf("non-TTY output must point at the password file; got: %s", out)
		}
		got, err := os.ReadFile(pwPath) //nolint:gosec // test-owned temp path
		if err != nil {
			t.Fatalf("password file: %v", err)
		}
		if string(got) != pw+"\n" {
			t.Errorf("file content = %q, want password", got)
		}
		info, err := os.Stat(pwPath)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %o, want 0600", perm)
		}
	})

	t.Run("non-tty refuses to clobber an unread password", func(t *testing.T) {
		dir := t.TempDir()
		authDB := filepath.Join(dir, "dashboard.db")
		var buf bytes.Buffer

		if err := emitBootstrapCredentials(&buf, false, pw, authDB); err != nil {
			t.Fatalf("first emit: %v", err)
		}
		if err := emitBootstrapCredentials(&buf, false, "new-pw", authDB); err == nil {
			t.Error("second emit should fail while the previous password file exists")
		}
	})
}
