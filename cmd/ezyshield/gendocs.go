package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// newGenDocsCmd returns a hidden, build-time-only command that generates
// shell completions and man pages from the real command tree (issue #225).
// It is deliberately NOT a user-facing command:
//   - Hidden keeps it out of --help output and shell completion suggestions.
//   - Cobra's doc.GenManTree skips hidden commands (IsAvailableCommand), so
//     it never generates a man page for itself.
//
// scripts/package/mk-completions-man.sh is the only intended caller,
// invoked from goreleaser's before hook. Building the *real* newRootCmd()
// tree (the same one main() runs) guarantees the shipped completions/man
// pages can never drift from the actual CLI surface — there is no separate
// stub command tree to keep in sync.
func newGenDocsCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:    "__gendocs <completions-dir> <man-dir>",
		Short:  "Generate shell completions and man pages (build-time only, not a user command)",
		Hidden: true,
		Args:   cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return genDocs(root, args[0], args[1])
		},
	}
}

// genDocs writes bash/zsh/fish completions under completionsDir/<shell>/
// and gzip-ready section-1 man pages under manDir/man1/, both derived from
// root's live command tree. Directories are created as needed (MkdirAll),
// so callers may pass paths that don't exist yet.
func genDocs(root *cobra.Command, completionsDir, manDir string) error {
	name := root.Name()

	bashDir := filepath.Join(completionsDir, "bash")
	zshDir := filepath.Join(completionsDir, "zsh")
	fishDir := filepath.Join(completionsDir, "fish")
	man1Dir := filepath.Join(manDir, "man1")

	for _, dir := range []string{bashDir, zshDir, fishDir, man1Dir} {
		// 0o750: these are build-output directories only (goreleaser's
		// before-hook stage, never shipped as-is — the packaging step
		// re-applies its own perms when placing files at FHS paths), but
		// gosec (G301) still wants the cap honored here.
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	if err := root.GenBashCompletionFile(filepath.Join(bashDir, name)); err != nil {
		return fmt.Errorf("generate bash completion: %w", err)
	}
	if err := root.GenZshCompletionFile(filepath.Join(zshDir, "_"+name)); err != nil {
		return fmt.Errorf("generate zsh completion: %w", err)
	}
	if err := root.GenFishCompletionFile(filepath.Join(fishDir, name+".fish"), true); err != nil {
		return fmt.Errorf("generate fish completion: %w", err)
	}

	// Source is deliberately static (not the build's version string): this
	// generator runs in goreleaser's `before.hooks` stage, which executes
	// before the version ldflags are known, so main.version would read the
	// "dev" placeholder — baking that into every shipped man page would be
	// misleading, not helpful.
	header := &doc.GenManHeader{
		Title:   strings.ToUpper(name),
		Section: "1",
		Source:  "EzyShield",
		Manual:  root.Short,
	}
	if err := doc.GenManTree(root, header, man1Dir); err != nil {
		return fmt.Errorf("generate man pages: %w", err)
	}
	return nil
}
