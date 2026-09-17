// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenDocs exercises the real generation path against the actual
// newRootCmd() tree (issue #225): the shipped completions/man pages must
// come from the same command tree main() runs, never a stub.
func TestGenDocs(t *testing.T) {
	root := newRootCmd()
	completionsDir := t.TempDir()
	manDir := t.TempDir()

	if err := genDocs(root, completionsDir, manDir); err != nil {
		t.Fatalf("genDocs: %v", err)
	}

	for _, tc := range []struct {
		name string
		path string
		// want is a substring that proves the file was generated from the
		// real command tree, not a stub. Bash's generator (GenBashCompletion,
		// the legacy static style) embeds subcommand names directly, so
		// "ban" is checked literally. Zsh/fish use cobra's modern dynamic
		// completion style: the script shells out to the binary's own
		// `__complete` at completion time instead of listing commands
		// statically, so the meaningful check there is that the script
		// wires itself up for our binary name and the dynamic protocol.
		want string
	}{
		{"bash completion", filepath.Join(completionsDir, "bash", "ezyshield"), "ban"},
		{"zsh completion", filepath.Join(completionsDir, "zsh", "_ezyshield"), "__complete"},
		{"fish completion", filepath.Join(completionsDir, "fish", "ezyshield.fish"), "complete -c ezyshield"},
		{"root man page", filepath.Join(manDir, "man1", "ezyshield.1"), "ban"},
		{"ban subcommand man page", filepath.Join(manDir, "man1", "ezyshield-ban.1"), "ban"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatalf("read %s: %v", tc.path, err)
			}
			if len(b) == 0 {
				t.Fatalf("%s is empty", tc.path)
			}
			if !strings.Contains(string(b), tc.want) {
				t.Errorf("%s does not contain %q", tc.path, tc.want)
			}
		})
	}
}

// TestGenDocsCreatesNestedDirs covers the empty/not-yet-existing input case
// (SECURITY-REVIEW.md §10 self-review: "what if input is empty/nil/zero?").
func TestGenDocsCreatesNestedDirs(t *testing.T) {
	root := newRootCmd()
	base := t.TempDir()
	completionsDir := filepath.Join(base, "does", "not", "exist", "completions")
	manDir := filepath.Join(base, "also", "missing", "man")

	if err := genDocs(root, completionsDir, manDir); err != nil {
		t.Fatalf("genDocs on nested non-existent dirs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(completionsDir, "bash", "ezyshield")); err != nil {
		t.Fatalf("bash completion not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(manDir, "man1", "ezyshield.1")); err != nil {
		t.Fatalf("root man page not created: %v", err)
	}
}

// TestGenDocsMkdirFailure covers the "external call fails" case: a path
// component that collides with an existing regular file makes os.MkdirAll
// fail, and genDocs must propagate that error instead of panicking or
// silently continuing.
func TestGenDocsMkdirFailure(t *testing.T) {
	root := newRootCmd()
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	err := genDocs(root, filepath.Join(blocker, "completions"), t.TempDir())
	if err == nil {
		t.Fatal("expected genDocs to fail when completions dir cannot be created")
	}
}

// TestGenDocsCmdHidden asserts the build-time-only command never leaks into
// the user-facing CLI surface (--help, shell completion suggestions) and is
// therefore also excluded from its own generated man tree by cobra.
func TestGenDocsCmdHidden(t *testing.T) {
	root := newRootCmd()
	for _, c := range root.Commands() {
		if c.Name() != "__gendocs" {
			continue
		}
		if !c.Hidden {
			t.Fatal("__gendocs must be Hidden — it is a build-time tool, not a user command")
		}
		return
	}
	t.Fatal("__gendocs command not registered on root")
}

// TestGenDocsRootManHasCommandList (issue #652): the top-level man page must
// be a usable table of contents — a COMMANDS section with each verb and its
// one-line description, plus EXAMPLES and FILES — not a bare SEE ALSO list.
func TestGenDocsRootManHasCommandList(t *testing.T) {
	root := newRootCmd()
	manDir := t.TempDir()
	if err := genDocs(root, t.TempDir(), manDir); err != nil {
		t.Fatalf("genDocs: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(manDir, "man1", "ezyshield.1")) //nolint:gosec // reads a file just generated in a t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	for _, want := range []string{".SH COMMANDS", ".SH EXAMPLES", ".SH FILES", "\\fBban\\fP", "\\fBwatch\\fP"} {
		if !strings.Contains(page, want) {
			t.Errorf("root man page missing %q", want)
		}
	}
	// A command's Short must appear verbatim (modulo roff hyphen escaping),
	// proving the list is generated from the live tree, not a stub.
	if !strings.Contains(page, manEscape("Stream live daemon events")) {
		t.Errorf("root man page does not carry the live command descriptions")
	}
}

// TestGenDocsSubcommandTitle (issue #652): each subcommand page carries its
// own .TH title, not the shared EZYSHIELD(1).
func TestGenDocsSubcommandTitle(t *testing.T) {
	root := newRootCmd()
	manDir := t.TempDir()
	if err := genDocs(root, t.TempDir(), manDir); err != nil {
		t.Fatalf("genDocs: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(manDir, "man1", "ezyshield-ban.1")) //nolint:gosec // reads a file just generated in a t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `.TH "EZYSHIELD-BAN"`) {
		t.Errorf("ezyshield-ban.1 has the wrong .TH title (want EZYSHIELD-BAN)")
	}
	// A nested command path is dash-joined too.
	nb, err := os.ReadFile(filepath.Join(manDir, "man1", "ezyshield-config-show.1")) //nolint:gosec // reads a file just generated in a t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(nb), `.TH "EZYSHIELD-CONFIG-SHOW"`) {
		t.Errorf("nested page has the wrong .TH title (want EZYSHIELD-CONFIG-SHOW)")
	}
}
