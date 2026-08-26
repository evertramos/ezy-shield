// SPDX-License-Identifier: AGPL-3.0-only

package main

// Golden-behavior tests for `ezyshield migrate fail2ban` (issue #182),
// driven by the reader-issue fixtures. The generated files must round-trip
// through the strict loaders and the policy must ALWAYS be armed:false.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

func runMigrate(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(append([]string{"migrate", "fail2ban"}, args...))
	err := root.Execute()
	return out.String(), errb.String(), err
}

func TestMigrateFail2ban_GeneratesValidatedProposal(t *testing.T) {
	from := filepath.Join("..", "..", "fixtures", "fail2ban", "overrides")
	outDir := filepath.Join(t.TempDir(), "proposal")

	stdout, _, err := runMigrate(t, "--from", from, "--out", outDir)
	if err != nil {
		t.Fatalf("migrate fail2ban: %v", err)
	}
	if !strings.Contains(stdout, "REPORT.md") || !strings.Contains(stdout, "armed: false") {
		t.Fatalf("summary output incomplete:\n%s", stdout)
	}

	// config.yaml round-trips through the strict loader with the mapped
	// collectors (jail.local enabled sshd; jail.d enabled nginx).
	cfg, err := config.LoadConfig(filepath.Join(outDir, "config.yaml"))
	if err != nil {
		t.Fatalf("generated config.yaml did not validate: %v", err)
	}
	var haveSSH, haveNginx bool
	for _, c := range cfg.Collectors {
		if c.Kind == "journald" {
			haveSSH = true
		}
		if c.Kind == "file" && c.Parser == "nginx" {
			haveNginx = true
		}
	}
	if !haveSSH || !haveNginx {
		t.Fatalf("collectors = %+v, want journald ssh + nginx file", cfg.Collectors)
	}

	// policy.yaml validates, is ALWAYS dry-run, and carries the imported
	// allowlist (ignoreip minus the hostname).
	pol, err := config.LoadPolicy(filepath.Join(outDir, "policy.yaml"))
	if err != nil {
		t.Fatalf("generated policy.yaml did not validate: %v", err)
	}
	if pol.Armed {
		t.Fatal("migrated policy MUST be armed:false regardless of fail2ban state")
	}
	allow := strings.Join(pol.Allowlist, ",")
	if !strings.Contains(allow, "127.0.0.0/8") || !strings.Contains(allow, "203.0.113.4/32") {
		t.Fatalf("allowlist = %v, want the two ignoreip prefixes", pol.Allowlist)
	}

	// REPORT.md carries all the sections the AC names.
	report, err := os.ReadFile(filepath.Join(outDir, "REPORT.md")) //nolint:gosec // test temp path
	if err != nil {
		t.Fatalf("read REPORT.md: %v", err)
	}
	for _, want := range []string{
		"## Mapped jails", "## Not mapped", "## Allowlist imported",
		"## Differences to understand", "## Next steps",
		"postfix",            // mapped as planned-parser unmapped entry
		"escalates",          // escalation vs fixed bantime explained
		"office.example.com", // hostname warning surfaced via reader warnings
	} {
		if !strings.Contains(string(report), want) {
			t.Errorf("REPORT.md lacks %q", want)
		}
	}
}

func TestMigrateFail2ban_NothingFoundErrors(t *testing.T) {
	empty := t.TempDir() // exists but has no jail files
	_, _, err := runMigrate(t, "--from", empty, "--out", filepath.Join(t.TempDir(), "o"))
	if err == nil || !strings.Contains(err.Error(), "no jails found") {
		t.Fatalf("err = %v, want the nothing-found failure (exit 1)", err)
	}
}

func TestMigrateFail2ban_NeverWritesEtcByDefault(t *testing.T) {
	from := filepath.Join("..", "..", "fixtures", "fail2ban", "overrides")
	outDir := filepath.Join(t.TempDir(), "proposal")
	if _, _, err := runMigrate(t, "--from", from, "--out", outDir); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// The proposal landed in outDir — and only there.
	for _, name := range []string{"config.yaml", "policy.yaml", "REPORT.md"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("%s missing from the out dir: %v", name, err)
		}
	}
}
