package main

// Per-component post-install wizards for the `config` group (issue #96).
// `config <kind> <name>` reconfigures ONE component of an existing
// installation: it reuses the same interactive sub-flow the init wizard
// runs, then merges the answers into the loaded config and commits them
// atomically (temp + rename, .bak backup, re-validation before save).
// The prompt/validation logic lives ONLY in the sub-flows (init_cdn.go,
// init_ai.go); this file owns the registry, the merge, and the write path.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/config"
)

// componentWizard drives the interactive prompts for one component and, on
// success, mutates cfg in place. It returns human-readable summary lines for
// the keys it changed, plus an optional postSave hook that runs only after
// config.yaml has been committed (e.g. writing a token to .env). A nil
// changed slice with a nil error means the operator aborted: nothing may be
// written.
type componentWizard func(ctx context.Context, p *wPrinter, pr prompter, deps cdnDeps,
	cfg *config.Config, configDir string) (changed []string, postSave func() error, err error)

// componentWizards is the single kind → name → wizard registry (issue #96).
// New components plug in here without further CLI changes.
var componentWizards = map[string]map[string]componentWizard{
	"enforcer": {
		"cloudflare": wizardEnforcerCloudflare,
	},
	"ai": {
		"anthropic": wizardAIProvider("anthropic"),
		"openai":    wizardAIProvider("openai"),
		"ollama":    wizardAIProvider("ollama"),
	},
	"collector": {
		"sshd":    wizardCollectorSSH,
		"nginx":   wizardCollectorWeb("nginx"),
		"apache":  wizardCollectorWeb("apache"),
		"traefik": wizardCollectorWeb("traefik"),
		"caddy":   wizardCollectorWeb("caddy"),
	},
	"enrich": {
		"maxmind": wizardEnrichMaxmind,
	},
	"notifier": {
		"telegram": wizardNotifierTelegram,
		"email":    wizardNotifierEmail,
		"slack":    wizardNotifierSlack,
		"discord":  wizardNotifierDiscord,
		"webhook":  wizardNotifierWebhook,
	},
}

// lookupComponentWizard resolves kind+name against the registry. Unknown
// values produce errors that list what IS available, so a typo never leaves
// the operator guessing.
func lookupComponentWizard(kind, name string) (componentWizard, error) {
	byName, ok := componentWizards[kind]
	if !ok {
		return nil, fmt.Errorf("unknown component kind %q (available: %s)",
			kind, strings.Join(sortedWizardKeys(componentWizards), ", "))
	}
	wiz, ok := byName[name]
	if !ok {
		return nil, fmt.Errorf("unknown %s %q (available: %s)",
			kind, name, strings.Join(sortedWizardKeys(byName), ", "))
	}
	return wiz, nil
}

func sortedWizardKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// newAskFuncs returns the ask/askBool prompt closures shared by the init
// wizard and the `config <kind> <name>` wizards. Prompts are written to out;
// answers come from sc. When yes is true both closures return the default
// without prompting and sc may be nil.
func newAskFuncs(sc *bufio.Scanner, out io.Writer, yes bool) (
	ask func(question, def string) string,
	askBool func(question string, def bool) bool,
) {
	ask = func(question, def string) string {
		if yes {
			return def
		}
		if def != "" {
			_, _ = fmt.Fprintf(out, "  %s [%s]: ", question, def)
		} else {
			_, _ = fmt.Fprintf(out, "  %s: ", question)
		}
		if sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				return line
			}
		}
		return def
	}
	askBool = func(question string, def bool) bool {
		if yes {
			return def
		}
		choices := "y/N"
		if def {
			choices = "Y/n"
		}
		_, _ = fmt.Fprintf(out, "  %s [%s]: ", question, choices)
		if sc.Scan() {
			lower := strings.ToLower(strings.TrimSpace(sc.Text()))
			if lower != "" {
				return lower == "y" || lower == "yes"
			}
		}
		return def
	}
	return ask, askBool
}

// newConfigComponentCmd builds the `config <kind> <name>` command for one
// component kind, backed by the shared registry.
func newConfigComponentCmd(kind, short string) *cobra.Command {
	configPath := defaultConfigDir + "/config.yaml"

	cmd := &cobra.Command{
		Use:   kind + " <name>",
		Short: short,
		Long: short + ` and update config.yaml in place.

The write is atomic (temp file + rename); the previous version is kept
as config.yaml.bak and the merged configuration is re-validated before
anything touches disk. Secret tokens are stored in the .env file next
to config.yaml (mode 0600) — never in config.yaml itself.

Available names: ` + strings.Join(sortedWizardKeys(componentWizards[kind]), ", "),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRootForWrites(cmd, configPath); err != nil {
				return err
			}
			sc := bufio.NewScanner(cmd.InOrStdin())
			ask, askBool := newAskFuncs(sc, cmd.OutOrStdout(), false)
			p := &wPrinter{w: cmd.OutOrStdout()}
			code := runConfigComponent(cmd.Context(), p,
				closurePrompter{askFn: ask, askBoolFn: askBool},
				cdnDeps{}, kind, args[0], configPath)
			if p.err != nil {
				return fmt.Errorf("writing output: %w", p.err)
			}
			if code != validateExitOK {
				return exitCodeError{code}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", configPath, "path to config.yaml")
	return cmd
}

// runConfigComponent is the shared execution path for every `config <kind>
// <name>` invocation. Exit codes mirror the other config verbs: 0 success,
// 1 unknown component / wizard aborted / write failed, 2 config not found.
func runConfigComponent(ctx context.Context, p *wPrinter, pr prompter, deps cdnDeps,
	kind, name, configPath string) int {
	wiz, err := lookupComponentWizard(kind, name)
	if err != nil {
		p.printf("ERROR: %v\n", err)
		return validateExitError
	}
	if statRegularFile(configPath) != fileOK {
		p.printf("ERROR: %s not found or unreadable — run the init wizard first, or pass --config.\n", configPath)
		return validateExitNotFound
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		p.printf("ERROR: %v\n", err)
		p.println("Fix the existing config (see 'config validate') before reconfiguring components.")
		return validateExitError
	}

	changed, postSave, err := wiz(ctx, p, pr, deps, cfg, filepath.Dir(configPath))
	if err != nil {
		p.printf("ERROR: %v\n", err)
		return validateExitError
	}
	if len(changed) == 0 {
		// The wizard already printed why (abort reason / banner).
		p.println("No changes were made.")
		return validateExitError
	}

	header := fmt.Sprintf("# EzyShield config — updated by 'config %s %s'.\n"+
		"# The previous version was saved as %s.bak (comments are not carried over).\n"+
		"# Secrets must use 'env:VARNAME' references, never inline values.\n\n",
		kind, name, filepath.Base(configPath))
	bak, err := config.SaveConfig(configPath, cfg, header)
	if err != nil {
		p.printf("ERROR: %v\n", err)
		return validateExitError
	}
	// Restore daemon ownership with whatever mode SaveConfig preserved.
	if st, serr := os.Stat(configPath); serr == nil {
		if oerr := applyDaemonOwnership(configPath, st.Mode().Perm()); oerr != nil {
			p.printf("  warning: could not set ownership on %s: %v\n", configPath, oerr)
		}
	}
	p.printf("  wrote %s\n", configPath)
	if bak != "" {
		p.printf("  backup:  %s\n", bak)
	}
	if postSave != nil {
		if err := postSave(); err != nil {
			p.printf("ERROR: %v\n", err)
			return validateExitError
		}
	}

	p.println("\nChanged keys:")
	for _, line := range changed {
		p.printf("  %s\n", line)
	}
	p.println("\nNext steps:")
	p.println("  config validate                — re-check the full configuration")
	p.println("  systemctl restart ezyshield    — apply to the running daemon")
	return validateExitOK
}

// wizardEnforcerCloudflare adapts the init CDN sub-flow (init_cdn.go) to
// post-install reconfiguration: same prompts, same dry token validation,
// same .env merge semantics — but merging into an existing Config instead
// of generating a fresh file. With accounts already configured (issue #217)
// the operator first picks between reconfiguring one of them and adding a
// new one; account entries merge by name (same name = replace).
func wizardEnforcerCloudflare(ctx context.Context, p *wPrinter, pr prompter, deps cdnDeps,
	cfg *config.Config, configDir string) ([]string, func() error, error) {
	var existing []config.CloudflareCfg
	if cfg.Enforce != nil {
		existing = cfg.Enforce.Cloudflare
	}

	opts := cfSubflowOpts{existing: existing}
	if len(existing) > 0 {
		p.println("  Existing Cloudflare account(s):")
		for _, ex := range existing {
			p.printf("    • %s — mode %s\n", cfAccountDisplayName(ex.Name), cfModeOrDefault(ex.Mode))
		}
		target, ok := pickCFReconfigureTarget(p, pr, existing)
		if !ok {
			p.println("  Nothing selected; no changes made.")
			return nil, nil, nil
		}
		if target != nil {
			opts.reconfigureName = *target
			opts.hasReconfigure = true
		}
	}

	step := &cdnStep{}
	runCloudflareSubflow(ctx, p, pr, step, deps, nil, opts)
	if !step.cfEnabled || len(step.cfAccounts) == 0 {
		// The sub-flow already printed the specific reason and the aborted
		// banner (issue #93); nothing was decided, nothing to save.
		return nil, nil, nil
	}

	if cfg.Enforce == nil {
		cfg.Enforce = &config.EnforceCfg{}
	}
	var changed []string
	for i := range step.cfAccounts {
		acct := &step.cfAccounts[i]
		verb := "added"
		replaced := false
		for j := range cfg.Enforce.Cloudflare {
			if cfg.Enforce.Cloudflare[j].Name == acct.cfg.Name {
				cfg.Enforce.Cloudflare[j] = acct.cfg
				verb = "replaced"
				replaced = true
				break
			}
		}
		if !replaced {
			cfg.Enforce.Cloudflare = append(cfg.Enforce.Cloudflare, acct.cfg)
		}
		changed = append(changed, cfChangedLines(verb, acct)...)
	}

	// Going multi-account can leave a legacy unnamed entry behind, which
	// config validation rejects (every account needs a unique name once
	// there is more than one). Name it now rather than failing the write.
	if len(cfg.Enforce.Cloudflare) > 1 {
		if err := nameUnnamedCFAccounts(p, pr, cfg.Enforce.Cloudflare); err != nil {
			return nil, nil, err
		}
	}

	postSave := func() error {
		envPath := filepath.Join(configDir, envFileName)
		for i := range step.cfAccounts {
			acct := &step.cfAccounts[i]
			wrote, kept, err := writeCloudflareEnvFile(configDir, acct.tokenEnvVar, acct.token)
			if err != nil {
				return err
			}
			switch {
			case kept:
				p.printf("  kept %s (existing %s preserved)\n", envPath, acct.tokenEnvVar)
			case wrote:
				p.printf("  wrote %s (chmod 600, %s merged)\n", envPath, acct.tokenEnvVar)
			}
		}
		return nil
	}
	return changed, postSave, nil
}

// cfAccountDisplayName renders an account label for terminal listings; the
// legacy single-account shape has no name.
func cfAccountDisplayName(name string) string {
	if name == "" {
		return "(unnamed)"
	}
	return name
}

// cfModeOrDefault mirrors the config loader's defaulting (empty = lists).
func cfModeOrDefault(mode string) string {
	if mode == "" {
		return "lists"
	}
	return mode
}

// pickCFReconfigureTarget asks which existing account the operator wants to
// redo. Returns (nil, true) for "add a new account", (&name, true) to
// reconfigure that entry, and (nil, false) when the answer matches nothing.
func pickCFReconfigureTarget(p *wPrinter, pr prompter, existing []config.CloudflareCfg) (*string, bool) {
	if len(existing) == 1 {
		if pr.askBool("Reconfigure this account (yes) or add a new one (no)?", true) {
			name := existing[0].Name
			return &name, true
		}
		return nil, true
	}
	ans := strings.TrimSpace(pr.ask("Account to reconfigure (exact name; ENTER to add a new one)", ""))
	if ans == "" {
		return nil, true
	}
	for _, ex := range existing {
		if ex.Name == ans {
			name := ex.Name
			return &name, true
		}
	}
	p.printf("  no account named %q exists.\n", ans)
	return nil, false
}

// cfChangedLines renders the changed-keys summary for one merged account.
func cfChangedLines(verb string, acct *cfAccountSetup) []string {
	label := "enforce.cloudflare"
	if acct.cfg.Name != "" {
		label = "enforce.cloudflare[" + acct.cfg.Name + "]"
	}
	lines := []string{
		fmt.Sprintf("%s — %s entry (mode=%s, action=%s, api_token=env:%s)",
			label, verb, acct.cfg.Mode, acct.cfg.Action, acct.tokenEnvVar),
	}
	switch acct.cfg.Mode {
	case "lists":
		lines = append(lines,
			label+".account_id = "+acct.cfg.AccountID,
			label+".list_name = "+acct.cfg.ListName)
	case "rulesets":
		lines = append(lines,
			label+".zone_ids = "+strings.Join(acct.cfg.ZoneIDs, ", "))
	}
	return lines
}

// nameUnnamedCFAccounts prompts a name for any unnamed entry once the config
// holds more than one account. The entry keeps its api_token reference —
// account labels and env-var names are independent, so no .env change is
// needed. Returns an error (aborting the whole write) when the operator
// cannot supply a valid unique name: writing a config that fails validation
// is never an option.
func nameUnnamedCFAccounts(p *wPrinter, pr prompter, accounts []config.CloudflareCfg) error {
	used := make(map[string]bool, len(accounts))
	for _, a := range accounts {
		if a.Name != "" {
			used[a.Name] = true
		}
	}
	for i := range accounts {
		if accounts[i].Name != "" {
			continue
		}
		p.println("  The pre-existing account has no name; with multiple accounts every entry needs one.")
		name := strings.TrimSpace(pr.ask("Name for the pre-existing account (e.g. main)", "main"))
		if !cfNameRe.MatchString(name) || used[name] {
			return fmt.Errorf("invalid or duplicate account name %q — aborting without changes", name)
		}
		accounts[i].Name = name
		used[name] = true
		p.printf("  named the pre-existing account %q (its api_token env var is unchanged)\n", name)
	}
	return nil
}

// wizardAIProvider adapts the init AI sub-flow (init_ai.go) to post-install
// reconfiguration for one provider: same model + key-source prompts, same
// no-echo token read and placeholder semantics — merged into the existing
// Config's ai: section instead of a freshly generated file. Skipping the
// paste is a valid outcome (placeholder path, issue #13 §5), so unlike the
// Cloudflare wizard this one never aborts.
func wizardAIProvider(provider string) componentWizard {
	return func(_ context.Context, p *wPrinter, pr prompter, deps cdnDeps,
		cfg *config.Config, configDir string) ([]string, func() error, error) {
		step := &aiStep{provider: provider}
		runAIProviderSubflow(p, pr, step, deps.TokenReader, false)

		verb := "added"
		if cfg.AI != nil && cfg.AI.Provider != "" {
			verb = "replaced"
		}
		if cfg.AI == nil {
			// Fresh ai: section — same tuning defaults the init wizard emits.
			cfg.AI = &config.AICfg{
				AmbiguousBand:    [2]int{30, 75},
				TokenBudgetDaily: 100000,
			}
		}
		cfg.AI.Provider = step.provider
		cfg.AI.Model = step.model
		cfg.AI.APIKey = ""
		if step.keyEnvVar != "" {
			cfg.AI.APIKey = config.SecretRef("env:" + step.keyEnvVar)
		}

		changed := []string{
			fmt.Sprintf("ai — %s provider (provider=%s, model=%s)", verb, step.provider, step.model),
		}
		if step.keyEnvVar != "" {
			changed = append(changed, "ai.api_key = env:"+step.keyEnvVar)
		}
		if len(cfg.AI.Providers) > 0 {
			p.println("  note: ai.providers (failover chain) is set and takes precedence over" +
				" the single-provider fields — edit config.yaml manually if that is not intended.")
		}

		postSave := func() error {
			if step.keyEnvVar == "" || step.externalKey {
				// ollama has no key; option-2 keys are managed outside .env.
				return nil
			}
			wrote, kept, err := writeAIEnvFile(configDir, step.keyEnvVar, step.token)
			if err != nil {
				return err
			}
			envPath := filepath.Join(configDir, envFileName)
			switch {
			case kept:
				p.printf("  kept %s (existing %s preserved)\n", envPath, step.keyEnvVar)
			case wrote && step.token == "":
				p.printf("  wrote %s (chmod 600, placeholder — set %s there, then restart the daemon)\n",
					envPath, step.keyEnvVar)
			case wrote:
				p.printf("  wrote %s (chmod 600, %s merged)\n", envPath, step.keyEnvVar)
			}
			return nil
		}
		return changed, postSave, nil
	}
}
