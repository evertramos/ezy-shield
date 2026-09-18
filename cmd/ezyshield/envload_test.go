// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigDirEnv(t *testing.T) {
	dir := t.TempDir()
	env := "# a comment\n" +
		"TELEGRAM_BOT_TOKEN=123456:ABCdef\n" +
		"QUOTED_TOKEN=\"with spaces\"\n" +
		"ALREADY_SET=from_file\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	// A var already in the environment must win over the file.
	t.Setenv("ALREADY_SET", "from_env")
	// Ensure the loaded vars don't leak past the test.
	t.Cleanup(func() {
		_ = os.Unsetenv("TELEGRAM_BOT_TOKEN")
		_ = os.Unsetenv("QUOTED_TOKEN")
	})

	loadConfigDirEnv(dir)

	if got := os.Getenv("TELEGRAM_BOT_TOKEN"); got != "123456:ABCdef" {
		t.Errorf("TELEGRAM_BOT_TOKEN = %q, want the .env value", got)
	}
	if got := os.Getenv("QUOTED_TOKEN"); got != "with spaces" {
		t.Errorf("QUOTED_TOKEN = %q, want the unquoted value", got)
	}
	if got := os.Getenv("ALREADY_SET"); got != "from_env" {
		t.Errorf("ALREADY_SET = %q, want the pre-set env value (file must not override)", got)
	}
}

func TestLoadConfigDirEnv_MissingFileIsNoOp(t *testing.T) {
	// No .env in the dir → must not panic or set anything.
	loadConfigDirEnv(t.TempDir())
	loadConfigDirEnv("")
}
