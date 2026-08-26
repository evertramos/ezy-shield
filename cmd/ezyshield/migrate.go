package main

// `ezyshield migrate fail2ban` (issue #182): read fail2ban's effective jail
// configuration (internal/migrate, issue #181), map it to EzyShield
// concepts, and write a proposed config.yaml + policy.yaml + REPORT.md.
//
// Safety contract: NEVER touches /etc unless --write is passed explicitly;
// the default output is ./ezyshield-migration (or --out). --write refuses
// to overwrite existing files without --force. The generated policy is
// ALWAYS armed:false regardless of fail2ban's state, and both files are
// validated through the strict loaders before a single byte is written.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/migrate"
)

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate configuration from other ban tools",
	}
	cmd.AddCommand(newMigrateFail2banCmd())
	return cmd
}

func newMigrateFail2banCmd() *cobra.Command {
	var (
		fromDir string
		outDir  string
		write   bool
		force   bool
	)

	cmd := &cobra.Command{
		Use:   "fail2ban",
		Short: "Read a fail2ban install and propose an equivalent EzyShield setup",
		Long: `Read fail2ban's effective jail configuration (jail.conf, jail.local,
jail.d/ with fail2ban's precedence) and generate a proposed config.yaml,
policy.yaml, and REPORT.md.

Nothing under /etc is touched unless you pass --write. The default writes
the proposal into ./ezyshield-migration for review; the generated policy is
ALWAYS armed: false (dry-run) regardless of fail2ban's state. The report
lists every mapped jail, everything that could not be mapped (with the
filter name), the imported allowlist, and the standing differences
(escalation ladder vs fixed bantime).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMigrateFail2ban(cmd, fromDir, outDir, write, force)
		},
	}

	cmd.Flags().StringVar(&fromDir, "from", "/etc/fail2ban", "fail2ban configuration directory")
	cmd.Flags().StringVar(&outDir, "out", "ezyshield-migration",
		"output directory for the proposed files")
	cmd.Flags().BoolVar(&write, "write", false,
		"write config.yaml/policy.yaml to /etc/ezyshield instead of --out (still never arms)")
	cmd.Flags().BoolVar(&force, "force", false,
		"with --write: overwrite existing /etc/ezyshield files")

	return cmd
}

func runMigrateFail2ban(cmd *cobra.Command, fromDir, outDir string, write, force bool) error {
	f2b, err := migrate.ReadFail2ban(fromDir)
	if err != nil {
		return fmt.Errorf("reading fail2ban configuration: %w", err)
	}
	if len(f2b.Jails) == 0 {
		return fmt.Errorf("no jails found under %s — is this a fail2ban configuration directory?", fromDir)
	}
	m := migrate.MapToEzyShield(f2b)

	cfgData, err := renderMigrationConfig(m)
	if err != nil {
		return err
	}
	polData, err := renderMigrationPolicy(m)
	if err != nil {
		return err
	}
	report := renderMigrationReport(fromDir, f2b, m)

	targetDir := outDir
	if write {
		targetDir = "/etc/ezyshield"
		if !force {
			for _, name := range []string{"config.yaml", "policy.yaml"} {
				if _, err := os.Stat(filepath.Join(targetDir, name)); err == nil {
					return fmt.Errorf("%s already exists — --write refuses to overwrite without --force", filepath.Join(targetDir, name))
				}
			}
		}
	}
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return fmt.Errorf("creating %s: %w", targetDir, err)
	}

	files := map[string][]byte{
		"config.yaml": cfgData,
		"policy.yaml": polData,
		"REPORT.md":   []byte(report),
	}
	for _, name := range []string{"config.yaml", "policy.yaml", "REPORT.md"} {
		path := filepath.Join(targetDir, name)
		if err := os.WriteFile(path, files[name], 0o640); err != nil { //nolint:gosec // 0640 matches init's config writes; no secrets in these files
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}

	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), map[string]any{
			"out":       targetDir,
			"mapped":    len(m.Mapped),
			"unmapped":  len(m.Unmapped),
			"skipped":   len(m.Skipped),
			"allowlist": len(m.Allowlist),
			"warnings":  len(f2b.Warnings),
		})
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "wrote %s (config.yaml, policy.yaml, REPORT.md)\n", targetDir)                  //nolint:errcheck
	fmt.Fprintf(out, "mapped %d jail(s), %d unmapped, %d disabled/skipped — details in REPORT.md\n", //nolint:errcheck
		len(m.Mapped), len(m.Unmapped), len(m.Skipped))
	fmt.Fprintf(out, "the generated policy is armed: false (dry-run) — review, run '%s doctor', watch a\n", //nolint:errcheck
		progName)
	fmt.Fprintf(out, "week of dry-run output, then arm with '%s arm'\n", progName) //nolint:errcheck
	return nil
}

// renderMigrationConfig builds a config.yaml from the mapping and validates
// it through the strict loader.
func renderMigrationConfig(m *migrate.Migration) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# EzyShield config — generated by '" + progName + " migrate fail2ban'\n")
	b.WriteString("# Review before use; see REPORT.md next to this file.\n\n")
	b.WriteString("data_dir: /var/lib/ezyshield\n")
	fmt.Fprintf(&b, "socket_path: %s\n", daemonSockPath)
	b.WriteString("log:\n  level: info\n")

	if len(m.Collectors) == 0 {
		b.WriteString("collectors: []\n")
	} else {
		b.WriteString("collectors:\n")
		for _, c := range m.Collectors {
			switch c.Kind {
			case "journald":
				fmt.Fprintf(&b, "  - kind: journald\n    unit: %s\n", c.Unit)
			case "file":
				fmt.Fprintf(&b, "  - kind: file\n    path: %s\n    parser: %s\n", c.Path, c.Parser)
			}
		}
	}

	data := []byte(b.String())
	if _, err := config.LoadConfigReader(bytes.NewReader(data), "migrated config"); err != nil {
		return nil, fmt.Errorf("generated config.yaml failed validation: %w", err)
	}
	return data, nil
}

// renderMigrationPolicy builds a policy.yaml (ALWAYS armed:false) carrying
// the imported allowlist, validated through the strict loader.
func renderMigrationPolicy(m *migrate.Migration) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# EzyShield policy — generated by '" + progName + " migrate fail2ban'\n")
	b.WriteString("# ALWAYS starts in dry-run; arm explicitly after reviewing dry-run output.\n\n")
	b.WriteString("armed: false\n")
	fmt.Fprintf(&b, "ban_threshold: %d\n", config.DefaultBanThreshold)
	fmt.Fprintf(&b, "observe_threshold: %d\n", config.DefaultObserveThreshold)
	b.WriteString("strikes:\n")
	for _, s := range config.DefaultStrikes {
		fmt.Fprintf(&b, "  - ttl: %s\n", fmtStrikeTTL(s.TTL.AsDuration()))
	}
	fmt.Fprintf(&b, "max_bans_per_minute: %d\n", config.DefaultMaxBansPerMinute)
	if len(m.Allowlist) > 0 {
		b.WriteString("# Imported from fail2ban ignoreip (validated IPs/CIDRs only).\n")
		b.WriteString("allowlist:\n")
		for _, p := range m.Allowlist {
			fmt.Fprintf(&b, "  - %s\n", p)
		}
	}
	b.WriteString("admin_cidrs: []\n")

	data := []byte(b.String())
	if _, err := config.LoadPolicyReader(bytes.NewReader(data), "migrated policy"); err != nil {
		return nil, fmt.Errorf("generated policy.yaml failed validation: %w", err)
	}
	return data, nil
}

// renderMigrationReport builds REPORT.md. All jail-derived strings come from
// the operator's own fail2ban tree (not attacker log content), but lengths
// are already capped by the reader.
func renderMigrationReport(fromDir string, f2b *migrate.Config, m *migrate.Migration) string {
	var b strings.Builder
	b.WriteString("# EzyShield migration report (fail2ban)\n\n")
	fmt.Fprintf(&b, "Source: `%s`\n\n", fromDir)

	if len(m.Mapped) > 0 {
		b.WriteString("## Mapped jails\n\n| Jail | maxretry | findtime | bantime | How |\n|---|---|---|---|---|\n")
		for _, mj := range m.Mapped {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				mj.Jail.Name, orDash(mj.Jail.MaxRetry), durDash(mj.Jail.FindTime), durDash(mj.Jail.BanTime), mj.How)
		}
	}
	if len(m.Unmapped) > 0 {
		b.WriteString("\n## Not mapped\n\n| Jail | Reason |\n|---|---|\n")
		for _, uj := range m.Unmapped {
			fmt.Fprintf(&b, "| %s | %s |\n", uj.Jail.Name, uj.Reason)
		}
	}
	if len(m.Skipped) > 0 {
		fmt.Fprintf(&b, "\n## Disabled jails (skipped)\n\n%s\n", strings.Join(m.Skipped, ", "))
	}
	if len(m.Allowlist) > 0 {
		b.WriteString("\n## Allowlist imported from ignoreip\n\n")
		for _, p := range m.Allowlist {
			fmt.Fprintf(&b, "- `%s`\n", p)
		}
	}
	b.WriteString("\n## Differences to understand\n\n")
	for _, n := range m.Notes {
		fmt.Fprintf(&b, "- %s\n", n)
	}
	if m.BanTimeSuggestion > 0 {
		fmt.Fprintf(&b, "- Largest fail2ban bantime seen: %s — if you want a comparable first strike, set the first `strikes:` ttl in policy.yaml accordingly (the ladder still escalates from there).\n",
			m.BanTimeSuggestion)
	}
	if len(f2b.Warnings) > 0 {
		b.WriteString("\n## Reader warnings\n\n")
		for _, w := range f2b.Warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
	}
	b.WriteString("\n## Next steps\n\n")
	b.WriteString("1. Review config.yaml and policy.yaml (they are proposals, not truth).\n")
	fmt.Fprintf(&b, "2. Install them (or re-run with `--write`), then run `%s doctor`.\n", progName)
	b.WriteString("3. Run a week in dry-run; watch `" + progName + " watch` / `list`.\n")
	fmt.Fprintf(&b, "4. Arm with `%s arm` once the dry-run output looks right.\n", progName)
	b.WriteString("5. Only then disable fail2ban (running both is safe but redundant).\n")
	return b.String()
}

func orDash(n int) string {
	if n == 0 {
		return "—"
	}
	return fmt.Sprintf("%d", n)
}

func durDash(d time.Duration) string {
	if d == 0 {
		return "—"
	}
	return d.String()
}
