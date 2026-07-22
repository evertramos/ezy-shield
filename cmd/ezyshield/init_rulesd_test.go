package main

// Tests for the init-side half of the rules.d overlay (issue #136): the
// rules.d dir is created for every install, the WordPress flow writes a
// commented tuning template instead of materializing the ruleset, re-runs
// never clobber operator edits, and the template stays in sync with the
// engine schema.

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/evertramos/ezy-shield/configs"
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

// uncommentedTemplateYAML writes a fresh WordPress template to a temp file
// and returns its commented rules block with the comment prefix stripped —
// i.e. the YAML an operator gets by uncommenting the whole block.
func uncommentedTemplateYAML(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "10-wordpress.yaml")
	if _, err := writeWordPressDropin(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatal(err)
	}

	var lines []string
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
			lines = append(lines, strings.TrimPrefix(line, "# "))
		case line == "#":
			lines = append(lines, "")
		default:
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		t.Fatal("template has no commented rules block")
	}
	return strings.Join(lines, "\n")
}

// TestWriteWordPressDropin_TemplateValidatesWhenUncommented guards the
// template against drifting from the engine schema: the commented rules
// block, once uncommented, must load and validate as a real drop-in that
// overrides the built-in WordPress rules.
func TestWriteWordPressDropin_TemplateValidatesWhenUncommented(t *testing.T) {
	t.Parallel()
	dropDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dropDir, "10-wordpress.yaml"), //nolint:gosec // test-owned temp path
		[]byte(uncommentedTemplateYAML(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.New("", dropDir); err != nil {
		t.Fatalf("uncommented template failed to load/validate — it drifted from the engine schema: %v", err)
	}
}

// TestWriteWordPressDropin_TemplateValuesMatchEmbeddedBase pins the
// template's commented values to the current embedded base. The template
// header promises "current built-in values as of the version that generated
// this file" — so retuning a base rule (threshold, score, matcher, …) must
// fail here until the template in writeWordPressDropin is refreshed to
// match. Schema validity alone (the test above) would let the template
// silently advertise stale defaults.
func TestWriteWordPressDropin_TemplateValuesMatchEmbeddedBase(t *testing.T) {
	t.Parallel()
	// One permissive struct for both sides: unknown fields in the embedded
	// base (e.g. matchers the template doesn't use) are ignored, which is
	// fine — we compare exactly the fields the template shows.
	type rule struct {
		Name        string   `yaml:"name"`
		Description string   `yaml:"description"`
		Kinds       []string `yaml:"kinds"`
		Field       string   `yaml:"field"`
		Contains    string   `yaml:"contains"`
		Window      string   `yaml:"window"`
		Threshold   int      `yaml:"threshold"`
		Score       int      `yaml:"score"`
		Category    string   `yaml:"category"`
	}
	type file struct {
		Rules []rule `yaml:"rules"`
	}

	var tmpl file
	if err := yaml.Unmarshal([]byte(uncommentedTemplateYAML(t)), &tmpl); err != nil {
		t.Fatalf("parse uncommented template: %v", err)
	}
	if len(tmpl.Rules) == 0 {
		t.Fatal("uncommented template has no rules")
	}

	data, err := configs.FS.ReadFile("rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var base file
	if err := yaml.Unmarshal(data, &base); err != nil {
		t.Fatalf("parse embedded rules.yaml: %v", err)
	}
	baseByName := make(map[string]rule, len(base.Rules))
	for _, r := range base.Rules {
		baseByName[r.Name] = r
	}

	for _, tr := range tmpl.Rules {
		br, ok := baseByName[tr.Name]
		if !ok {
			t.Errorf("template rule %q does not exist in the embedded base", tr.Name)
			continue
		}
		if !reflect.DeepEqual(tr, br) {
			t.Errorf("template values for %q drifted from the embedded base — update the template in writeWordPressDropin\n  template: %+v\n  base:     %+v",
				tr.Name, tr, br)
		}
	}
}
