package main

// Tests for the init-side half of the rules.d overlay (issue #136): the
// rules.d dir is created for every install, the WordPress flow writes a
// commented tuning template instead of materializing the ruleset, re-runs
// never clobber operator edits, and the template stays in sync with the
// engine schema.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/rules"
)

func TestEnsureRulesDir_CreatesAndIsIdempotent(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "rules.d")
	for i := 0; i < 2; i++ {
		if err := ensureRulesDir(dir); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("rules.d not a dir: %v", err)
	}
}

func TestWriteWordPressDropin_WritesCommentedTemplate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "10-wordpress.yaml")

	wrote, err := writeWordPressDropin(path)
	if err != nil {
		t.Fatalf("writeWordPressDropin: %v", err)
	}
	if !wrote {
		t.Fatal("first run must write")
	}

	// The template must be inert: loading it as a drop-in changes nothing
	// (every rule line is commented out).
	base, err := rules.New("", "")
	if err != nil {
		t.Fatalf("base engine: %v", err)
	}
	overlay, err := rules.New("", dir)
	if err != nil {
		t.Fatalf("engine with template drop-in: %v", err)
	}
	if len(base.Windows()) != len(overlay.Windows()) {
		t.Errorf("commented template changed the effective rules")
	}

	// Idempotency: a re-run keeps the existing file byte-for-byte.
	before, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	wrote, err = writeWordPressDropin(path)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if wrote {
		t.Error("second run must keep, not rewrite")
	}
	after, _ := os.ReadFile(path) //nolint:gosec // test-owned temp path
	if string(before) != string(after) {
		t.Error("re-run modified the operator's file")
	}
}

// TestWriteWordPressDropin_TemplateValidatesWhenUncommented guards the
// template against drifting from the engine schema: the commented rules
// block, once uncommented, must load and validate as a real drop-in that
// overrides the built-in WordPress rules.
func TestWriteWordPressDropin_TemplateValidatesWhenUncommented(t *testing.T) {
	t.Parallel()
	tmpl := t.TempDir()
	path := filepath.Join(tmpl, "10-wordpress.yaml")
	if _, err := writeWordPressDropin(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatal(err)
	}

	// Extract the commented YAML: from the "# rules:" line onward, strip
	// the comment prefix.
	var yaml []string
	in := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "# rules:") {
			in = true
		}
		if !in {
			continue
		}
		switch {
		case strings.HasPrefix(line, "# "):
			yaml = append(yaml, strings.TrimPrefix(line, "# "))
		case line == "#":
			yaml = append(yaml, "")
		default:
			yaml = append(yaml, line)
		}
	}
	if len(yaml) == 0 {
		t.Fatal("template has no commented rules block")
	}

	dropDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dropDir, "10-wordpress.yaml"), //nolint:gosec // test-owned temp path
		[]byte(strings.Join(yaml, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.New("", dropDir); err != nil {
		t.Fatalf("uncommented template failed to load/validate — it drifted from the engine schema: %v", err)
	}
}
