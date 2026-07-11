package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

func minimalConfig() *config.Config {
	return &config.Config{
		DataDir: "/var/lib/ezyshield",
		Collectors: []config.CollectorCfg{
			{Kind: "journald", Unit: "sshd"},
		},
	}
}

func TestSaveConfig_FreshFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")

	bak, err := config.SaveConfig(path, minimalConfig(), "# header\n")
	if err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	if bak != "" {
		t.Errorf("bak = %q, want empty for fresh file", bak)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 0640", st.Mode().Perm())
	}
	loaded, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("saved file does not load: %v", err)
	}
	if loaded.DataDir != "/var/lib/ezyshield" {
		t.Errorf("data_dir = %q", loaded.DataDir)
	}
	raw, _ := os.ReadFile(path) //nolint:gosec // test path
	if !strings.HasPrefix(string(raw), "# header\n") {
		t.Errorf("header missing:\n%s", raw)
	}
}

func TestSaveConfig_BackupAndModePreserved(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	const original = "data_dir: /old\ncollectors:\n  - kind: journald\n    unit: old\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	bak, err := config.SaveConfig(path, minimalConfig(), "")
	if err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	if bak != path+".bak" {
		t.Errorf("bak = %q, want %q", bak, path+".bak")
	}
	got, err := os.ReadFile(bak) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("reading backup: %v", err)
	}
	if string(got) != original {
		t.Errorf("backup content = %q, want original", got)
	}
	for _, p := range []string{path, bak} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want original 0600 preserved", p, st.Mode().Perm())
		}
	}
	// No stray temp files left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestSaveConfig_RefusesInvalid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	const original = "data_dir: /old\ncollectors:\n  - kind: journald\n    unit: old\n"
	//nolint:gosec // test file, intentional 0640 permission
	if err := os.WriteFile(path, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}

	bad := minimalConfig()
	bad.Collectors[0].Kind = "bogus"
	if _, err := config.SaveConfig(path, bad, ""); err == nil {
		t.Fatal("expected error for invalid config")
	}

	// Original untouched, no backup created.
	got, _ := os.ReadFile(path) //nolint:gosec // test path
	if string(got) != original {
		t.Errorf("original was modified on refused save:\n%s", got)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Errorf(".bak must not exist after refused save (err=%v)", err)
	}
}

func TestSaveConfig_NilRefused(t *testing.T) {
	t.Parallel()
	if _, err := config.SaveConfig(filepath.Join(t.TempDir(), "c.yaml"), nil, ""); err == nil {
		t.Fatal("expected error for nil config")
	}
}
