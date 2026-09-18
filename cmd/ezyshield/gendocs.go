// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
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

	if err := genManPages(root, man1Dir); err != nil {
		return fmt.Errorf("generate man pages: %w", err)
	}
	return nil
}

// genManPages writes one man page per visible command, like cobra's
// doc.GenManTree, but with two corrections (issue #652): each page gets its
// OWN .TH title (EZYSHIELD-BAN(1), not EZYSHIELD(1) on every page), and the
// root page carries a COMMANDS/EXAMPLES/FILES section the default generator
// omits — so `man ezyshield` is a usable table of contents instead of a
// bare SEE ALSO list. Command descriptions come from the live tree, so they
// cannot drift from the CLI.
func genManPages(cmd *cobra.Command, man1Dir string) error {
	for _, c := range cmd.Commands() {
		// Mirror cobra's own skip rules: hidden/deprecated verbs, the help
		// topic, and the build-time __gendocs command never get a page.
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if err := genManPages(c, man1Dir); err != nil {
			return err
		}
	}

	// Source is deliberately static (not the build's version string): this
	// generator runs in goreleaser's before.hooks stage, before the version
	// ldflags are known, so main.version would read "dev".
	header := &doc.GenManHeader{
		Title:   strings.ToUpper(strings.ReplaceAll(cmd.CommandPath(), " ", "-")),
		Section: "1",
		Source:  "EzyShield",
		Manual:  rootOf(cmd).Short,
	}
	var buf bytes.Buffer
	if err := doc.GenMan(cmd, header, &buf); err != nil {
		return fmt.Errorf("generate man page for %q: %w", cmd.CommandPath(), err)
	}
	page := buf.Bytes()
	if !cmd.HasParent() {
		page = injectRootSections(cmd, page)
	}

	basename := strings.ReplaceAll(cmd.CommandPath(), " ", "-") + ".1"
	//nolint:gosec // man1Dir is a build-output path, basename is a fixed command name
	if err := os.WriteFile(filepath.Join(man1Dir, basename), page, 0o644); err != nil {
		return fmt.Errorf("write man page %s: %w", basename, err)
	}
	return nil
}

// rootOf returns the top-most ancestor of cmd.
func rootOf(cmd *cobra.Command) *cobra.Command {
	for cmd.HasParent() {
		cmd = cmd.Parent()
	}
	return cmd
}

// manTP writes one roff tagged paragraph: a bold term and its description.
func manTP(b *strings.Builder, term, desc string) {
	b.WriteString(".TP\n")
	b.WriteString("\\fB")
	b.WriteString(manEscape(term))
	b.WriteString("\\fP\n")
	b.WriteString("\\&")
	b.WriteString(manEscape(desc))
	b.WriteString("\n")
}

// manExample writes a captioned, literal (no-fill) command block.
func manExample(b *strings.Builder, caption, cmds string) {
	b.WriteString(".PP\n")
	b.WriteString("\\&")
	b.WriteString(manEscape(caption))
	b.WriteString("\n.PP\n.RS\n.nf\n")
	b.WriteString(manEscape(cmds))
	b.WriteString("\n.fi\n.RE\n")
}

// injectRootSections splices COMMANDS, EXAMPLES and FILES into the root man
// page just before SEE ALSO, keeping the section order conventional
// (DESCRIPTION, OPTIONS, COMMANDS, EXAMPLES, FILES, SEE ALSO).
func injectRootSections(root *cobra.Command, page []byte) []byte {
	name := root.Name()
	var b strings.Builder

	b.WriteString(".SH COMMANDS\n")
	for _, c := range root.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		manTP(&b, c.Name(), c.Short)
	}

	b.WriteString(".SH EXAMPLES\n")
	manExample(&b, "Interactive first-time setup:", name+" init")
	manExample(&b, "Start the daemon (normally run via systemd):", name+" run")
	manExample(&b, "Daemon and enforcer health, then a full environment check:", name+" status\n"+name+" doctor")
	manExample(&b, "Manually ban and later lift an address:", name+" ban 203.0.113.7\n"+name+" unban 203.0.113.7")
	manExample(&b, "List active bans and stream live detections:", name+" list\n"+name+" watch")

	b.WriteString(".SH FILES\n")
	manTP(&b, "/etc/ezyshield/config.yaml", "Collectors, enforcers, and AI provider configuration.")
	manTP(&b, "/etc/ezyshield/policy.yaml", "Ban thresholds, allowlist, and the strike ladder.")
	manTP(&b, "/etc/ezyshield/.env", "Secrets (API keys) loaded by the systemd unit; not group- or world-readable.")
	manTP(&b, "/var/lib/ezyshield/ezyshield.db", "SQLite store of active bans and the audit log.")
	manTP(&b, "/run/ezyshield/ezyshield.sock", "Daemon control socket (root and the ezyshield group).")
	b.WriteString(".PP\nRun ")
	b.WriteString("\\fB" + manEscape(name) + " \\fICOMMAND\\fB \\-\\-help\\fP")
	b.WriteString(" or ")
	b.WriteString("\\fBman " + manEscape(name) + "\\-\\fICOMMAND\\fP")
	b.WriteString(" for detail on any command.\n")

	marker := []byte(".SH SEE ALSO")
	if i := bytes.Index(page, marker); i >= 0 {
		out := make([]byte, 0, len(page)+b.Len())
		out = append(out, page[:i]...)
		out = append(out, b.String()...)
		out = append(out, page[i:]...)
		return out
	}
	return append(page, b.String()...)
}

// manEscape renders developer-authored text safe for roff: a backslash
// becomes \e and a hyphen \- so groff keeps it literal (matching how
// cobra's own generator escapes command text).
func manEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\e")
	return strings.ReplaceAll(s, "-", "\\-")
}
