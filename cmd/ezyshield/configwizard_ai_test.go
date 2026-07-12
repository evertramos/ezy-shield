package main

// Tests for `config ai <provider>` (issue #103 slice 3): the post-install AI
// wizard built on the shared sub-flow in init_ai.go. Secret discipline
// mirrors configwizard_test.go — pasted keys land only in .env (0600),
// never in config.yaml or on stdout.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// TestRunConfigComponent_AIHappyPath drives `config ai <provider>` end to
// end on a fresh installation for every registered provider: defaults
// accepted at each prompt, key pasted no-echo where the provider has one.
func TestRunConfigComponent_AIHappyPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		provider  string
		wantModel string
		wantKey   string // env var; "" = keyless provider, no .env expected
	}{
		{"anthropic", "claude-haiku-4-5-20251001", "ANTHROPIC_API_KEY"},
		{"openai", "gpt-4o-mini", "OPENAI_API_KEY"},
		{"ollama", "llama3", ""},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			cfgPath := writeFile(t, dir, "config.yaml", validConfig)
			const token = "ai-test-key-secret" //nolint:gosec // G101: test fake, not a real credential
			tokenReads := 0
			prompt := &scriptedPrompter{} // all defaults: model, choice "1"
			deps := cdnDeps{TokenReader: func(string) (string, error) {
				tokenReads++
				return token, nil
			}}

			out := captureStep(t, func(p *wPrinter) {
				if code := runConfigComponent(context.Background(), p, prompt, deps,
					"ai", tc.provider, cfgPath); code != validateExitOK {
					t.Errorf("exit code = %d, want 0", code)
				}
			})

			cfg, err := config.LoadConfig(cfgPath)
			if err != nil {
				t.Fatalf("saved config does not load: %v", err)
			}
			if cfg.AI == nil || cfg.AI.Provider != tc.provider || cfg.AI.Model != tc.wantModel {
				t.Fatalf("ai section wrong: %+v", cfg.AI)
			}
			// Fresh section carries the same tuning defaults init emits.
			if cfg.AI.AmbiguousBand != [2]int{30, 75} || cfg.AI.TokenBudgetDaily != 100000 {
				t.Errorf("fresh ai defaults wrong: %+v", cfg.AI)
			}
			raw, _ := os.ReadFile(cfgPath) //nolint:gosec // test path
			if strings.Contains(string(raw), token) {
				t.Errorf("config.yaml contains the raw key:\n%s", raw)
			}
			if strings.Contains(out, token) {
				t.Errorf("stdout leaks the key: %q", out)
			}
			// Pre-existing collector config survives the merge, .bak kept.
			if len(cfg.Collectors) != 1 || cfg.Collectors[0].Unit != "sshd" {
				t.Errorf("original collectors lost in merge: %+v", cfg.Collectors)
			}
			if bak, err := os.ReadFile(cfgPath + ".bak"); err != nil || string(bak) != validConfig { //nolint:gosec // test path
				t.Errorf(".bak missing or differs from original (err=%v)", err)
			}

			envPath := filepath.Join(dir, envFileName)
			if tc.wantKey == "" {
				if string(cfg.AI.APIKey) != "" {
					t.Errorf("api_key = %q, want empty for keyless provider", cfg.AI.APIKey)
				}
				if tokenReads != 0 {
					t.Errorf("token reader called %d times for keyless provider", tokenReads)
				}
				if _, err := os.Stat(envPath); !os.IsNotExist(err) {
					t.Errorf(".env must not exist for keyless provider (err=%v)", err)
				}
				return
			}
			if string(cfg.AI.APIKey) != "env:"+tc.wantKey {
				t.Errorf("api_key = %q, want env reference to %s", cfg.AI.APIKey, tc.wantKey)
			}
			envRaw, err := os.ReadFile(envPath) //nolint:gosec // test path
			if err != nil {
				t.Fatalf("expected .env: %v", err)
			}
			if !strings.Contains(string(envRaw), tc.wantKey+"="+token) {
				t.Errorf(".env missing key line:\n%s", envRaw)
			}
			if st, _ := os.Stat(envPath); st.Mode().Perm() != 0o600 {
				t.Errorf(".env mode = %o, want 0600", st.Mode().Perm())
			}
		})
	}
}

// TestRunConfigComponent_AIMergePreservesEnvLines: an existing .env line
// (Cloudflare token) must survive the AI key upsert — the post-install
// writer merges, it never owns the whole file.
func TestRunConfigComponent_AIMergePreservesEnvLines(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml", validConfig)
	writeFile(t, dir, envFileName, "# tokens\nCLOUDFLARE_API_TOKEN=cf-existing\n")
	deps := cdnDeps{TokenReader: func(string) (string, error) { return "sk-ant-new", nil }}

	captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, &scriptedPrompter{}, deps,
			"ai", "anthropic", cfgPath); code != validateExitOK {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	envRaw, err := os.ReadFile(filepath.Join(dir, envFileName)) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CLOUDFLARE_API_TOKEN=cf-existing", "ANTHROPIC_API_KEY=sk-ant-new", "# tokens"} {
		if !strings.Contains(string(envRaw), want) {
			t.Errorf(".env lost %q after merge:\n%s", want, envRaw)
		}
	}
}

// TestRunConfigComponent_AISkipPaste covers ENTER-to-skip at the key prompt:
// with a real key already in .env it is kept untouched; without one the
// placeholder is written — either way the config change still lands.
func TestRunConfigComponent_AISkipPaste(t *testing.T) {
	t.Parallel()
	skipDeps := cdnDeps{TokenReader: func(string) (string, error) { return "", nil }}

	t.Run("existing key kept", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig)
		writeFile(t, dir, envFileName, "ANTHROPIC_API_KEY=sk-ant-real\n")

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, &scriptedPrompter{}, skipDeps,
				"ai", "anthropic", cfgPath); code != validateExitOK {
				t.Errorf("exit code = %d, want 0", code)
			}
		})
		envRaw, _ := os.ReadFile(filepath.Join(dir, envFileName)) //nolint:gosec // test path
		if !strings.Contains(string(envRaw), "ANTHROPIC_API_KEY=sk-ant-real") ||
			strings.Contains(string(envRaw), envAPIKeyPlaceholder) {
			t.Errorf("existing real key must be kept, not overwritten:\n%s", envRaw)
		}
		if !strings.Contains(out, "kept") {
			t.Errorf("stdout should say the existing key was kept:\n%s", out)
		}
	})

	t.Run("placeholder written", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig)

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, &scriptedPrompter{}, skipDeps,
				"ai", "anthropic", cfgPath); code != validateExitOK {
				t.Errorf("exit code = %d, want 0", code)
			}
		})
		envRaw, err := os.ReadFile(filepath.Join(dir, envFileName)) //nolint:gosec // test path
		if err != nil {
			t.Fatalf("expected placeholder .env: %v", err)
		}
		if !strings.Contains(string(envRaw), "ANTHROPIC_API_KEY="+envAPIKeyPlaceholder) {
			t.Errorf(".env missing placeholder line:\n%s", envRaw)
		}
		if !strings.Contains(out, "placeholder") {
			t.Errorf("stdout should point at the placeholder:\n%s", out)
		}
	})
}

// TestRunConfigComponent_AIExternalEnvVar: option 2 (key already in an env
// var, e.g. from sops/vault) — the config references the operator's var and
// the wizard must neither prompt for the key nor touch .env.
func TestRunConfigComponent_AIExternalEnvVar(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml", validConfig)
	prompt := &scriptedPrompter{strings: []string{
		"",           // model → default
		"2",          // choice: external env var
		"MY_ANT_KEY", // its name
	}}
	deps := cdnDeps{TokenReader: func(string) (string, error) {
		t.Error("token reader must not be called for an external key")
		return "", nil
	}}

	captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, prompt, deps,
			"ai", "anthropic", cfgPath); code != validateExitOK {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("saved config does not load: %v", err)
	}
	if string(cfg.AI.APIKey) != "env:MY_ANT_KEY" {
		t.Errorf("api_key = %q, want env:MY_ANT_KEY", cfg.AI.APIKey)
	}
	if _, err := os.Stat(filepath.Join(dir, envFileName)); !os.IsNotExist(err) {
		t.Errorf(".env must not be created for an externally managed key (err=%v)", err)
	}
}

// TestRunConfigComponent_AIReplacesExisting: reconfiguring on top of an
// existing ai: section swaps the provider fields but preserves the
// operator's tuning (ambiguous_band, token_budget_daily).
func TestRunConfigComponent_AIReplacesExisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	existing := validConfig + `ai:
  provider: anthropic
  model: claude-haiku-4-5-20251001
  api_key: env:ANTHROPIC_API_KEY
  ambiguous_band: [20, 80]
  token_budget_daily: 5000
`
	cfgPath := writeFile(t, dir, "config.yaml", existing)
	deps := cdnDeps{TokenReader: func(string) (string, error) { return "sk-openai-new", nil }}

	out := captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, &scriptedPrompter{}, deps,
			"ai", "openai", cfgPath); code != validateExitOK {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("saved config does not load: %v", err)
	}
	if cfg.AI.Provider != "openai" || cfg.AI.Model != "gpt-4o-mini" ||
		string(cfg.AI.APIKey) != "env:OPENAI_API_KEY" {
		t.Errorf("provider fields not replaced: %+v", cfg.AI)
	}
	if cfg.AI.AmbiguousBand != [2]int{20, 80} || cfg.AI.TokenBudgetDaily != 5000 {
		t.Errorf("operator tuning lost on replace: %+v", cfg.AI)
	}
	if !strings.Contains(out, "replaced provider") {
		t.Errorf("summary should say 'replaced provider':\n%s", out)
	}
}

// TestRunConfigComponent_AIUnknownName: a typo lists what IS registered.
func TestRunConfigComponent_AIUnknownName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml", validConfig)

	out := captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, &scriptedPrompter{}, cdnDeps{},
			"ai", "mistral", cfgPath); code != validateExitError {
			t.Errorf("exit code = %d, want %d", code, validateExitError)
		}
	})
	for _, want := range []string{`unknown ai "mistral"`, "anthropic", "ollama", "openai"} {
		if !strings.Contains(out, want) {
			t.Errorf("error should name the miss and list providers, missing %q:\n%s", want, out)
		}
	}
}
