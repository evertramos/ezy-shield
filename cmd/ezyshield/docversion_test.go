// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot walks up from the test's working directory (the package dir under
// `go test`) until it finds go.mod, and returns that directory. This keeps the
// doc-consistency checks independent of where the test binary runs.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from test directory")
		}
		dir = parent
	}
}

// goModVersion returns the minor version from go.mod's `go X.Y` directive, e.g. "1.26".
func goModVersion(t *testing.T, root string) string {
	t.Helper()
	//nolint:gosec // G304: repo-root path derived from go.mod location, not user input
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	m := regexp.MustCompile(`(?m)^go (\d+\.\d+)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("no `go X.Y` directive found in go.mod")
	}
	return string(m[1])
}

// TestREADMEGoVersionMatchesGoMod guards against the README advertising a Go
// version that contradicts go.mod (issue #344). go.mod's `go 1.26` directive
// makes 1.26 the toolchain floor; a user who trusts a lower version in the
// README would fail to build with GOTOOLCHAIN=local.
func TestREADMEGoVersionMatchesGoMod(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	want := goModVersion(t, root) // e.g. "1.26"

	//nolint:gosec // G304: repo-root path derived from go.mod location, not user input
	b, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readme := string(b)

	// Every "Go <X.Y>+" requirement string must name go.mod's version.
	found := regexp.MustCompile(`Go (\d+\.\d+)\+`).FindAllStringSubmatch(readme, -1)
	if len(found) == 0 {
		t.Fatal("no `Go X.Y+` requirement string found in README.md")
	}
	for _, m := range found {
		if m[1] != want {
			t.Errorf("README states Go %s+, but go.mod requires go %s — keep them in sync", m[1], want)
		}
	}

	// The shields.io badge encodes the version too (badge/go-<ver>+-...).
	if strings.Contains(readme, "badge/go-") && !strings.Contains(readme, "badge/go-"+want+"+") {
		t.Errorf("README Go badge does not match go.mod version %s (expected shields badge `go-%s+`)", want, want)
	}
}
