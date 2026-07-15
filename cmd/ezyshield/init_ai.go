package main

// The AI-provider sub-flow shared by the init wizard (askQuestions in
// init.go) and the post-install `config ai <provider>` wizard
// (configwizard.go). The prompt and .env-handling logic lives ONLY here so
// both entry points behave identically — same fixed env-var table, same
// two-option key prompt (paste vs external env var, issue #22), same
// no-echo token read, same placeholder semantics (issue #13).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/evertramos/ezy-shield/internal/config"
)

// aiProviderKeyName maps the supported AI provider names to the fixed env var
// that will hold their API key. Ollama runs locally and has no key. This
// table is the single source of truth — the wizard never asks the operator
// for the env var NAME any more (issue #13 §1).
var aiProviderKeyName = map[string]string{
	"anthropic": "ANTHROPIC_API_KEY",
	"openai":    "OPENAI_API_KEY",
	"ollama":    "",
}

// aiProviderDefaultModel is the default offered at the model prompt, per
// provider. Providers absent from this table get no model prompt at all.
var aiProviderDefaultModel = map[string]string{
	"anthropic": "claude-haiku-4-5-20251001",
	"openai":    "gpt-4o-mini",
	"ollama":    "llama3",
}

// aiStep collects everything the AI provider sub-flow decides. Extracted
// (mirroring cdnStep) so init and `config ai <provider>` share one flow.
type aiStep struct {
	provider  string
	model     string
	keyEnvVar string
	// externalKey is true when the operator chose option 2 (“I already
	// have it in an env var”): the key lives outside our .env file and the
	// wizards must not write anything for it.
	externalKey bool
	// token holds the operator-typed API key between the prompt and the
	// .env write. Same discipline as wizardState.aiToken — never used in
	// any log/print/error path (issue #13 §6); String() below redacts it.
	token string
}

// String on *aiStep masks the token, mirroring wizardState.String(): a
// `slog.Debug("state", "s", step)` or a %+v in tests must never leak it.
func (s *aiStep) String() string {
	if s == nil {
		return "<nil aiStep>"
	}
	tokMark := "<empty>"
	if s.token != "" {
		tokMark = "<redacted>"
	}
	return fmt.Sprintf("aiStep{provider=%q model=%q keyEnvVar=%q external=%v token=%s}",
		s.provider, s.model, s.keyEnvVar, s.externalKey, tokMark)
}

// runAIProviderSubflow drives the model + key-source prompts for one
// provider (step.provider must be set by the caller). tokenRead == nil means
// the package-level tokenReader (/dev/tty, echo-suppressed); tests and the
// config wizard inject their own. skipKey mirrors init's --yes mode: the key
// prompts are skipped entirely and the placeholder path handles .env.
func runAIProviderSubflow(p *wPrinter, pr prompter, step *aiStep,
	tokenRead func(prompt string) (string, error), skipKey bool) {
	// The env var NAME is fixed per provider (issue #13 §1); unknown
	// providers (typo on the init free-text prompt) get no key at all.
	step.keyEnvVar = aiProviderKeyName[step.provider]
	if def, known := aiProviderDefaultModel[step.provider]; known {
		step.model = pr.ask("Model", def)
	}
	if step.keyEnvVar != "" && !skipKey {
		askAIKeySource(p, pr, step, tokenRead)
	}
}

// askAIKeySource presents the two-option API-key prompt (issue #22).
// Option 1 (default): read the actual key value echo-suppressed; store it in
// step.token for the .env write. Option 2 (advanced): operator supplies their
// own env var name (validated by config.ValidateEnvVarName, rejecting
// paste-mistake secrets); step.token stays empty and step.externalKey marks
// the key as managed outside .env.
func askAIKeySource(p *wPrinter, pr prompter, step *aiStep,
	tokenRead func(prompt string) (string, error)) {
	if tokenRead == nil {
		tokenRead = tokenReader
	}
	p.printf("\n  How do you want to provide the %s API key?\n", step.provider)
	p.println("    1) Paste it here — stored in the .env file next to config.yaml (recommended)")
	p.println("    2) I already have it in an env var (e.g. from sops / vault / LoadCredential)")
	choice := pr.ask("Choice", "1")
	if strings.TrimSpace(choice) == "2" {
		step.externalKey = true
		for attempt := 0; attempt < 3; attempt++ {
			name := pr.ask(
				fmt.Sprintf("Env var name holding the %s API key", step.provider),
				step.keyEnvVar)
			if err := config.ValidateEnvVarName(name); err != nil {
				p.printf("    invalid env var name: %v\n", err)
				continue
			}
			step.keyEnvVar = name
			return
		}
		p.println("    Too many invalid attempts; keeping the canonical env var name.")
		return
	}
	// Option 1: read the key echo-suppressed from /dev/tty.
	tok, err := tokenRead(
		fmt.Sprintf("  Paste your %s API key (input hidden, ENTER to skip): ", step.provider))
	if err != nil {
		// Cannot open /dev/tty (non-interactive / no controlling tty). Fall
		// through silently — the placeholder path handles the env file.
		step.token = ""
		return
	}
	step.token = tok
}

// writeAIEnvFile merges keyEnvVar into <configDir>/.env preserving every
// other line (e.g. CLOUDFLARE_API_TOKEN) — the post-install counterpart of
// writeOrKeepEnvFile, which owns the whole file at init time. Semantics:
//
//	token != ""                       → upsert KEY=token (rotation)
//	token == "", existing real value  → keep the file untouched (§5)
//	token == "", absent / placeholder → upsert the placeholder
//
// Mode + ownership match the init writes: 0600 root:ezyshield. wrote/kept
// mirror writeOrKeepEnvFile so callers print consistent log lines; the
// token itself never appears in any log path (issue #13 §6).
func writeAIEnvFile(configDir, keyEnvVar, token string) (wrote, kept bool, err error) {
	if keyEnvVar == "" {
		// Nothing to write (ollama); caller shouldn't have called us.
		return false, false, nil
	}
	envPath := filepath.Join(configDir, envFileName)
	existing, ok := readEnvValue(envPath, keyEnvVar)
	if token == "" && ok && existing != "" && existing != envAPIKeyPlaceholder {
		return false, true, nil
	}
	if token != "" && existing == token {
		return false, true, nil
	}
	value := token
	if value == "" {
		value = envAPIKeyPlaceholder
	}
	lines, err := loadEnvFileLines(envPath)
	if err != nil {
		return false, false, err
	}
	body := renderEnvFile(upsertEnvLine(lines, keyEnvVar, value))
	if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
		return false, false, fmt.Errorf("writing %s: %w", envPath, err)
	}
	if err := applyDaemonOwnership(envPath, 0o600); err != nil {
		return false, false, fmt.Errorf("set ownership on %s: %w", envPath, err)
	}
	return true, false, nil
}
