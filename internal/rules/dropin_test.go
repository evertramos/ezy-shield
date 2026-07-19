package rules_test

// Tests for the rules.d drop-in overlay (issue #136): embedded base always
// loaded, drop-ins merged by rule name in lexical file order, fail-closed on
// any invalid drop-in, and a WARN on shadowing an existing rule.

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/rules"
)

// writeDropin writes content to dir/name and fails the test on error.
func writeDropin(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write drop-in %s: %v", name, err)
	}
}

// engineWindows returns the window set as a map for lookup.
func engineWindows(e *rules.Engine) map[time.Duration]bool {
	out := make(map[time.Duration]bool)
	for _, w := range e.Windows() {
		out[w] = true
	}
	return out
}

func TestDropin_MissingDirIsBaseOnly(t *testing.T) {
	t.Parallel()
	base, err := rules.New("", "")
	if err != nil {
		t.Fatalf("base: %v", err)
	}
	overlay, err := rules.New("", filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing dir must not error: %v", err)
	}
	if len(base.Windows()) != len(overlay.Windows()) {
		t.Errorf("missing dir changed the rule set: base windows %v, overlay windows %v",
			base.Windows(), overlay.Windows())
	}
}

func TestDropin_AddsNewRule(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeDropin(t, dir, "50-local.yaml", `
rules:
  - name: local_admin_probe
    kinds: [http_request]
    field: path
    contains: /secret-admin
    window: 90s
    threshold: 2
    score: 70
    category: scanner
`)
	e, err := rules.New("", dir)
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	// New rule's window joins the union.
	if !engineWindows(e)[90*time.Second] {
		t.Errorf("Windows() missing the drop-in's 90s window: %v", e.Windows())
	}
	// And the rule actually fires.
	agg := makeAgg(ip1, 90*time.Second, nil)
	agg.Sample = append(agg.Sample, httpEvent("404", "/secret-admin"), httpEvent("404", "/secret-admin/x"))
	agg.Kinds = map[string]int{"http_request": 2}
	agg.Count = 2
	verdicts := e.Evaluate(context.Background(), agg)
	found := false
	for _, v := range verdicts {
		if strings.Contains(v.Reason, "local_admin_probe") {
			found = true
		}
	}
	if !found {
		t.Errorf("drop-in rule did not fire; verdicts=%+v", verdicts)
	}
}

func TestDropin_OverridesBaseRuleByName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Base http_wp_probe: threshold 3. Raise it to 10 via drop-in.
	writeDropin(t, dir, "10-wordpress.yaml", `
rules:
  - name: http_wp_probe
    kinds: [http_request]
    field: path
    contains: wp-login
    window: 60s
    threshold: 10
    score: 80
    category: scanner
`)
	e, err := rules.New("", dir)
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	// 5 wp-login hits: fires with base threshold (3), must NOT fire with
	// the overridden threshold (10).
	var sample = makeAgg(ip1, w60, nil)
	for i := 0; i < 5; i++ {
		sample.Sample = append(sample.Sample, httpEvent("200", "/wp-login.php"))
	}
	sample.Kinds = map[string]int{"http_request": 5}
	sample.Count = 5
	for _, v := range e.Evaluate(context.Background(), sample) {
		if strings.Contains(v.Reason, "http_wp_probe:") {
			t.Errorf("overridden rule fired below its new threshold: %+v", v)
		}
	}
}

func TestDropin_LexicalOrderLaterWins(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rule := func(threshold int) string {
		return `
rules:
  - name: order_test_rule
    kinds: [http_request]
    window: 60s
    threshold: ` + map[int]string{2: "2", 9: "9"}[threshold] + `
    score: 50
    category: scanner
`
	}
	writeDropin(t, dir, "10-first.yaml", rule(2))
	writeDropin(t, dir, "20-second.yaml", rule(9))
	e, err := rules.New("", dir)
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	agg := makeAgg(ip1, w60, nil)
	agg.Kinds = map[string]int{"http_request": 5}
	agg.Count = 5
	// 5 events: fires under 10-first (threshold 2) but 20-second raised it
	// to 9 — the later file must win.
	for _, v := range e.Evaluate(context.Background(), agg) {
		if strings.Contains(v.Reason, "order_test_rule") {
			t.Errorf("earlier drop-in won over later one: %+v", v)
		}
	}
}

func TestDropin_FailClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string
	}{
		{"malformed yaml", "rules: [;;;"},
		{"unknown field", "rules:\n  - name: x\n    kinds: [a]\n    window: 60s\n    threshold: 1\n    score: 10\n    category: c\n    surprise: true\n"},
		{"invalid rule fails merged validation", "rules:\n  - name: bad\n    kinds: [a]\n    window: 60s\n    threshold: 0\n    score: 10\n    category: c\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeDropin(t, dir, "50-broken.yaml", tt.content)
			if _, err := rules.New("", dir); err == nil {
				t.Fatal("want fail-closed error, got nil")
			}
		})
	}
}

func TestDropin_CommentsOnlyFileIsFine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeDropin(t, dir, "10-wordpress.yaml", "# tuning template\n# rules:\n#   - name: http_wp_probe\n")
	base, err := rules.New("", "")
	if err != nil {
		t.Fatalf("base: %v", err)
	}
	e, err := rules.New("", dir)
	if err != nil {
		t.Fatalf("comments-only drop-in must not error: %v", err)
	}
	if len(base.Windows()) != len(e.Windows()) {
		t.Errorf("comments-only drop-in changed the rule set")
	}
}

func TestDropin_IgnoresNonYAMLAndHidden(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeDropin(t, dir, "README.txt", "not yaml at all {{{")
	writeDropin(t, dir, ".50-hidden.yaml", "rules: [;;;")
	if err := os.Mkdir(filepath.Join(dir, "sub.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.New("", dir); err != nil {
		t.Fatalf("non-yaml/hidden/dir entries must be ignored: %v", err)
	}
}

func TestDropin_LegacyRulesPathDisablesOverlay(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Drop-in would add a 90s-window rule…
	writeDropin(t, dir, "50-local.yaml", `
rules:
  - name: local_admin_probe
    kinds: [http_request]
    window: 90s
    threshold: 2
    score: 70
    category: scanner
`)
	// …but rules_path is set, so ONLY that file loads.
	override := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(override, []byte(`
rules:
  - name: only_rule
    kinds: [http_request]
    window: 45s
    threshold: 1
    score: 10
    category: scanner
`), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := rules.New(override, dir)
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	ws := engineWindows(e)
	if !ws[45*time.Second] || ws[90*time.Second] || len(ws) != 1 {
		t.Errorf("legacy rules_path must load exclusively (want only 45s): %v", e.Windows())
	}
}

func TestDropin_OverrideLogsWarn(t *testing.T) {
	// Captures slog output — cannot run in parallel with tests that also
	// touch the default logger.
	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	dir := t.TempDir()
	writeDropin(t, dir, "10-wordpress.yaml", `
rules:
  - name: http_wp_probe
    kinds: [http_request]
    field: path
    contains: wp-login
    window: 60s
    threshold: 10
    score: 80
    category: scanner
`)
	if _, err := rules.New("", dir); err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "http_wp_probe") {
		t.Errorf("expected WARN naming the overridden rule; log=%q", out)
	}
	if !strings.Contains(out, "new_threshold=10") {
		t.Errorf("WARN should carry old/new threshold; log=%q", out)
	}
}
