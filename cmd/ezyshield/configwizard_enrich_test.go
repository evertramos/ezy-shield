package main

// Tests for `config enrich maxmind` (issue #168). Secret discipline mirrors
// configwizard_notifier_test.go: the pasted MaxMind license key lands only
// in .env (0600) — never in config.yaml or on stdout. Table-driven with
// scripted prompts per AGENTS.md Go Conventions.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// enrichEntry is appended to validConfig when a test needs a pre-existing
// enrich section.
const enrichEntry = `enrich:
  db_path: /old/Country.mmdb
  asn_path: /old/ASN.mmdb
  auto_update: true
  license_key: env:MAXMIND_LICENSE_KEY
`

// TestRunConfigComponent_EnrichHappyPath drives the wizard end to end on a
// fresh installation across the auto_update / key-source combinations.
func TestRunConfigComponent_EnrichHappyPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		answers       []string // scripted `ask` answers, in prompt order
		bools         []bool   // scripted `askBool` answers, in prompt order
		tokens        []string // successive no-echo secret reads
		wantEnv       []string // KEY=value lines that must be present in .env
		wantNoEnvFile bool
		check         func(t *testing.T, e *config.EnrichCfg)
	}{
		{
			name: "auto_update with pasted key",
			// db path (default), asn path (default), key choice 1
			answers: []string{"", "", "1"},
			bools:   []bool{true, true}, // configure? / auto_update?
			tokens:  []string{"mm-license-secret"},
			wantEnv: []string{"MAXMIND_LICENSE_KEY=mm-license-secret"},
			check: func(t *testing.T, e *config.EnrichCfg) {
				if string(e.LicenseKey) != "env:MAXMIND_LICENSE_KEY" {
					t.Fatalf("license_key = %q, want env ref", e.LicenseKey)
				}
				if e.DBPath != defaultCountryDBPath || e.ASNPath != defaultASNDBPath {
					t.Errorf("paths = %q, %q — want defaults", e.DBPath, e.ASNPath)
				}
				if !e.AutoUpdate {
					t.Error("auto_update = false, want true")
				}
			},
		},
		{
			name: "auto_update with operator-managed env var",
			// db path, asn path, key choice 2, env var name
			answers:       []string{"/data/Country.mmdb", "/data/ASN.mmdb", "2", "MY_MM_KEY"},
			bools:         []bool{true, true},
			wantNoEnvFile: true,
			check: func(t *testing.T, e *config.EnrichCfg) {
				if string(e.LicenseKey) != "env:MY_MM_KEY" {
					t.Fatalf("license_key = %q, want env:MY_MM_KEY", e.LicenseKey)
				}
				if e.DBPath != "/data/Country.mmdb" || e.ASNPath != "/data/ASN.mmdb" {
					t.Errorf("paths = %q, %q", e.DBPath, e.ASNPath)
				}
			},
		},
		{
			name:          "manual databases without auto_update",
			answers:       []string{"", ""},
			bools:         []bool{true, false}, // configure? / auto_update off
			wantNoEnvFile: true,
			check: func(t *testing.T, e *config.EnrichCfg) {
				if e.AutoUpdate {
					t.Error("auto_update = true, want false")
				}
				if e.LicenseKey.IsSet() {
					t.Errorf("license_key = %q, want unset", e.LicenseKey)
				}
			},
		},
		{
			name:    "pasted key skipped leaves placeholder",
			answers: []string{"", "", "1"},
			bools:   []bool{true, true},
			tokens:  []string{""}, // ENTER at the paste prompt
			wantEnv: []string{"MAXMIND_LICENSE_KEY="},
			check: func(t *testing.T, e *config.EnrichCfg) {
				if string(e.LicenseKey) != "env:MAXMIND_LICENSE_KEY" {
					t.Fatalf("license_key = %q, want env ref even on skip", e.LicenseKey)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			cfgPath := writeFile(t, dir, "config.yaml", validConfig)
			prompt := &scriptedPrompter{strings: tc.answers, bools: tc.bools}
			deps := cdnDeps{TokenReader: notifierTokenReader(tc.tokens...)}

			out := captureStep(t, func(p *wPrinter) {
				if code := runConfigComponent(context.Background(), p, prompt, deps,
					"enrich", "maxmind", cfgPath); code != validateExitOK {
					t.Errorf("exit code = %d, want 0", code)
				}
			})

			cfg, err := config.LoadConfig(cfgPath)
			if err != nil {
				t.Fatalf("saved config does not load: %v", err)
			}
			if cfg.Enrich == nil {
				t.Fatal("enrich section missing after wizard")
			}
			tc.check(t, cfg.Enrich)

			// Secrets: never in config.yaml, never on stdout, only in .env.
			raw, _ := os.ReadFile(cfgPath) //nolint:gosec // test path
			for _, tok := range tc.tokens {
				if tok == "" {
					continue
				}
				if strings.Contains(string(raw), tok) {
					t.Errorf("config.yaml contains the raw license key:\n%s", raw)
				}
				if strings.Contains(out, tok) {
					t.Errorf("stdout leaks the license key: %q", out)
				}
			}
			envPath := filepath.Join(dir, envFileName)
			if tc.wantNoEnvFile {
				if _, err := os.Stat(envPath); !os.IsNotExist(err) {
					t.Errorf(".env exists but no secret should have been written")
				}
			} else {
				envRaw, err := os.ReadFile(envPath) //nolint:gosec // test path
				if err != nil {
					t.Fatalf("expected .env: %v", err)
				}
				for _, want := range tc.wantEnv {
					if !strings.Contains(string(envRaw), want) {
						t.Errorf(".env missing %q:\n%s", want, envRaw)
					}
				}
				if st, _ := os.Stat(envPath); st.Mode().Perm() != 0o600 {
					t.Errorf(".env mode = %o, want 0600", st.Mode().Perm())
				}
			}

			// Pre-existing config survives; .bak holds the original.
			if len(cfg.Collectors) != 1 || cfg.Collectors[0].Unit != "sshd" {
				t.Errorf("original collectors lost in merge: %+v", cfg.Collectors)
			}
			if bak, err := os.ReadFile(cfgPath + ".bak"); err != nil || string(bak) != validConfig { //nolint:gosec // test path
				t.Errorf(".bak missing or differs from original (err=%v)", err)
			}
			for _, want := range []string{"Changed keys:", "enrich —", "config validate"} {
				if !strings.Contains(out, want) {
					t.Errorf("stdout missing %q:\n%s", want, out)
				}
			}
		})
	}
}

// TestRunConfigComponent_EnrichReplacesExisting reconfigures an existing
// enrich section in place.
func TestRunConfigComponent_EnrichReplacesExisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml", validConfig+enrichEntry)
	prompt := &scriptedPrompter{
		strings: []string{"/new/Country.mmdb", "/new/ASN.mmdb"},
		bools:   []bool{true, false},
	}

	out := captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
			"enrich", "maxmind", cfgPath); code != validateExitOK {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("saved config does not load: %v", err)
	}
	e := cfg.Enrich
	if e == nil || e.DBPath != "/new/Country.mmdb" || e.AutoUpdate || e.LicenseKey.IsSet() {
		t.Fatalf("enrich = %+v, want replaced manual-mode section", e)
	}
	if !strings.Contains(out, "replaced section") {
		t.Errorf("stdout missing replace verb:\n%s", out)
	}
}

// TestRunConfigComponent_EnrichRemove covers the answered-no paths: nothing
// configured (no-op), decline removal, and confirmed removal.
func TestRunConfigComponent_EnrichRemove(t *testing.T) {
	t.Parallel()

	t.Run("nothing configured", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig)
		prompt := &scriptedPrompter{bools: []bool{false}}

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"enrich", "maxmind", cfgPath); code != validateExitError {
				t.Errorf("exit code = %d, want 1 (nothing to do)", code)
			}
		})
		if !strings.Contains(out, "nothing to do") {
			t.Errorf("stdout missing no-op notice:\n%s", out)
		}
	})

	t.Run("confirmed removal", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig+enrichEntry)
		prompt := &scriptedPrompter{bools: []bool{false, true}} // configure? no / remove? yes

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"enrich", "maxmind", cfgPath); code != validateExitOK {
				t.Errorf("exit code = %d, want 0", code)
			}
		})

		cfg, err := config.LoadConfig(cfgPath)
		if err != nil {
			t.Fatalf("saved config does not load: %v", err)
		}
		if cfg.Enrich != nil {
			t.Fatalf("enrich = %+v, want removed", cfg.Enrich)
		}
		if !strings.Contains(out, "removed section") {
			t.Errorf("stdout missing removal summary:\n%s", out)
		}
	})

	t.Run("declined removal", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		original := validConfig + enrichEntry
		cfgPath := writeFile(t, dir, "config.yaml", original)
		prompt := &scriptedPrompter{bools: []bool{false, false}}

		captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"enrich", "maxmind", cfgPath); code != validateExitError {
				t.Errorf("exit code = %d, want 1 (aborted)", code)
			}
		})
		raw, _ := os.ReadFile(cfgPath) //nolint:gosec // test path
		if string(raw) != original {
			t.Errorf("config.yaml changed on declined removal:\n%s", raw)
		}
	})
}
