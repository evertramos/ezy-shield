package config

// Tests for the runtime armed accessor and the surgical policy.yaml rewrite
// (issue #228).

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestIsArmedSetArmed_Concurrent(t *testing.T) {
	t.Parallel()
	p := &Policy{Armed: false}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); p.SetArmed(true) }()
		go func() { defer wg.Done(); _ = p.IsArmed() }()
	}
	wg.Wait()
	if !p.IsArmed() {
		t.Error("IsArmed = false after SetArmed(true)")
	}
}

const armPolicyFixture = `# EzyShield policy — hand-tuned, comments must survive rewrites
armed: false   # flip with 'ezyshield arm', not by hand
ban_threshold: 70
observe_threshold: 40
# strikes ladder below
strikes:
  - ttl: 5m
allowlist:
  - 203.0.113.0/24
admin_cidrs:
  - 198.51.100.0/24
max_bans_per_minute: 30
`

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	return path
}

func TestRewriteArmed_FlipsValueAndPreservesEverythingElse(t *testing.T) {
	t.Parallel()
	path := writeFixture(t, armPolicyFixture)

	if err := RewriteArmed(path, true); err != nil {
		t.Fatalf("RewriteArmed(true): %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(armPolicyFixture,
		"armed: false   # flip with 'ezyshield arm', not by hand",
		"armed: true   # flip with 'ezyshield arm', not by hand", 1)
	if string(got) != want {
		t.Errorf("rewrite changed more than the armed value:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// The rewritten file must still load and reflect the new value.
	pol, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy after rewrite: %v", err)
	}
	if !pol.Armed {
		t.Error("policy loaded armed=false after RewriteArmed(true)")
	}

	// And flip back.
	if err := RewriteArmed(path, false); err != nil {
		t.Fatalf("RewriteArmed(false): %v", err)
	}
	got, _ = os.ReadFile(path) //nolint:gosec // test-owned path
	if string(got) != armPolicyFixture {
		t.Error("flipping back did not restore the original file byte-for-byte")
	}
}

func TestRewriteArmed_PreservesFileMode(t *testing.T) {
	t.Parallel()
	path := writeFixture(t, armPolicyFixture)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RewriteArmed(path, true); err != nil {
		t.Fatalf("RewriteArmed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestRewriteArmed_RefusesAmbiguousFiles(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		content string
	}{
		{"no armed line", "ban_threshold: 70\n"},
		// An indented armed key (e.g. inside a nested map) must not match;
		// with no top-level line the rewrite has nothing safe to change.
		{"only nested armed", "sub:\n  armed: false\nban_threshold: 70\n"},
		{"two armed lines", "armed: false\nban_threshold: 70\narmed: true\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := writeFixture(t, tc.content)
			if err := RewriteArmed(path, true); err == nil {
				t.Fatal("want refusal on ambiguous file, got nil")
			}
			got, _ := os.ReadFile(path) //nolint:gosec // test-owned path
			if string(got) != tc.content {
				t.Error("refused rewrite still modified the file")
			}
		})
	}
}
