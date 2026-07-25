package main

// Non-interactive driver for `ezyshield init` (issue #231). This is a
// different DRIVER over the same steps the interactive wizard runs — it never
// forks the wizard's detection or config/policy generation. Environment
// detection (detectEnvironment) and YAML generation (renderGeneratedConfig /
// renderGeneratedPolicy) are shared verbatim; this file only replaces the
// interactive Q&A (askQuestions) with an answers-file + flags decoder and adds
// the automation-specific guarantees: atomic writes, --force idempotency, a
// --json summary, and a hard "secrets only via env references" boundary.
//
// Security boundary (Hard Rule 3): the answers file and every flag carry env
// var NAMES only. A literal secret — pasted as api_key/api_token, or slipped
// into an *_env value — is rejected with a pointed message before anything is
// written. The generated config carries credentials only as `env:VARNAME`
// references; the real values live in .env (mode 0600), populated by the
// operator's own secret management.

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/evertramos/ezy-shield/internal/config"
)

// initAnswers is the schema of the --answers YAML file. It mirrors the
// interactive wizard's decision surface. It is a contract — documented in the
// automation guide. Unknown keys are rejected (KnownFields), so a typo fails
// loudly instead of silently doing nothing.
//
// Secrets NEVER appear here. Credential-bearing components reference an
// environment variable NAME only (api_key_env, api_token_env). The literal
// api_key / api_token fields exist ONLY as traps: a value there produces a
// pointed rejection (rejectLiteralSecrets) rather than a generic "unknown
// key" error.
type initAnswers struct {
	Collectors answersCollectors `yaml:"collectors"`
	Allowlist  answersAllowlist  `yaml:"allowlist"`
	AI         answersAI         `yaml:"ai"`
	Enforce    answersEnforce    `yaml:"enforce"`
}

type answersCollectors struct {
	// SSH toggles journald SSH monitoring. A pointer so an omitted key (nil)
	// is distinguishable from an explicit false: omitted defaults to true
	// (the wizard default), false disables.
	SSH *bool                 `yaml:"ssh"`
	Web []answersWebCollector `yaml:"web"`
}

type answersWebCollector struct {
	Kind      string `yaml:"kind"`      // file | docker
	Path      string `yaml:"path"`      // required for kind: file
	Container string `yaml:"container"` // required for kind: docker
	Parser    string `yaml:"parser"`    // nginx | apache | apache-error | traefik | caddy
}

type answersAllowlist struct {
	AdminIPs []string `yaml:"admin_ips"`
}

type answersAI struct {
	Enabled   bool   `yaml:"enabled"`
	Provider  string `yaml:"provider"`
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
	// APIKey is a trap for a pasted literal key — see rejectLiteralSecrets.
	APIKey string `yaml:"api_key"`
}

type answersEnforce struct {
	Cloudflare []answersCloudflare `yaml:"cloudflare"`
}

type answersCloudflare struct {
	Name        string   `yaml:"name"`
	Mode        string   `yaml:"mode"` // lists (default) | rulesets
	AccountID   string   `yaml:"account_id"`
	ListName    string   `yaml:"list_name"`
	ZoneIDs     []string `yaml:"zone_ids"`
	Action      string   `yaml:"action"`
	APITokenEnv string   `yaml:"api_token_env"`
	// APIToken is a trap for a pasted literal token — see rejectLiteralSecrets.
	APIToken string `yaml:"api_token"`
}

// runNonInteractiveInit is the scripted counterpart of runInitWizard. Order is
// deliberate: every validation runs and can abort BEFORE the first byte is
// written, so a bad or incomplete answers file leaves no partial config
// (issue #231 "nothing half-written").
func runNonInteractiveInit(cmd *cobra.Command, configDir string, skipSystem, force bool, answersPath string) error {
	// In --json mode, human-readable progress goes to stderr so stdout carries
	// only the machine-readable summary a caller can parse.
	progW := cmd.OutOrStdout()
	if jsonOutput {
		progW = cmd.ErrOrStderr()
	}
	p := &wPrinter{w: progW}
	st := newStyler(progW)

	// 1. Load + strictly parse the answers file (unknown keys => error).
	answers, err := loadInitAnswers(answersPath)
	if err != nil {
		return err
	}
	// 2. Flags override file values.
	applyFlagOverrides(cmd, answers)

	// 3. Reject any literal secret before touching disk (Hard Rule 3).
	if err := rejectLiteralSecrets(answers); err != nil {
		return err
	}

	// 4. Validate every answer at once — one error listing ALL problems.
	if problems := validateAnswers(answers); len(problems) > 0 {
		return fmt.Errorf("non-interactive init: %d problem(s) in the answers:\n  - %s",
			len(problems), strings.Join(problems, "\n  - "))
	}

	// 5. Refuse to clobber an existing config unless --force — identical
	//    idempotency semantics to the interactive preflight.
	if !force {
		if err := preflightExistingConfigFiles(configDir); err != nil {
			return fmt.Errorf("%w (pass --force to overwrite)", err)
		}
	}

	p.println("")
	p.println(st.header("EzyShield setup (non-interactive)"))
	if !skipSystem && os.Getuid() != 0 {
		return fmt.Errorf("init requires root — re-run with sudo or as root")
	}

	// 6. Detection still runs; answers pin/override the result.
	state := &wizardState{}
	sum := &initSummary{}
	if err := detectEnvironment(p, st, state, configDir, nil, true, skipSystem); err != nil {
		return err
	}

	// 7. Apply the answers onto the detected state (fills the same fields
	//    askQuestions would have). armed is forced false inside applyAnswers.
	applyAnswers(state, answers)
	if len(state.adminIPs) == 0 {
		p.println(st.warn("admin_cidrs will be EMPTY — set allowlist.admin_ips (or --admin-ips) so a"))
		p.println(st.warn("management IP survives; 'ezyshield arm' flags an empty list before arming."))
	}
	summarizeChoices(state, sum, false)

	// 8. Render AND validate BOTH files before writing EITHER — a validation
	//    failure here means nothing reaches /etc/ezyshield.
	cfgData, err := renderGeneratedConfig(state)
	if err != nil {
		return err
	}
	polData, err := renderGeneratedPolicy(state)
	if err != nil {
		return err
	}

	// 9. Writes begin here. Ownership bootstrap first (so a User=ezyshield
	//    daemon can read what we write), same as the wizard's Files step.
	p.println("")
	p.println(st.header("Files"))
	if !skipSystem {
		if err := createEzyshieldUser(p.w); err != nil {
			p.printf("  warning: could not create ezyshield user: %v\n", err)
		}
		if err := addAdminToEzyshieldGroup(p.w); err != nil {
			p.printf("  warning: could not add admin to ezyshield group: %v\n", err)
		}
	}
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		return fmt.Errorf("creating config dir %s: %w", configDir, err)
	}
	if err := applyDaemonOwnership(configDir, 0o750); err != nil {
		return fmt.Errorf("set ownership on %s: %w", configDir, err)
	}

	configPath := filepath.Join(configDir, "config.yaml")
	policyPath := filepath.Join(configDir, "policy.yaml")

	// Atomic two-file commit: stage both to temp files, then rename both, so a
	// mid-write failure never leaves a half-written pair (issue #231).
	if err := commitTwoFilesAtomic(configPath, cfgData, policyPath, polData, 0o640); err != nil {
		return err
	}
	if err := applyDaemonOwnership(configPath, 0o640); err != nil {
		return fmt.Errorf("set ownership on %s: %w", configPath, err)
	}
	if err := applyDaemonOwnership(policyPath, 0o640); err != nil {
		return fmt.Errorf("set ownership on %s: %w", policyPath, err)
	}
	p.println(st.ok("wrote " + configPath))
	p.println(st.ok(fmt.Sprintf("wrote %s (armed: %v)", policyPath, state.armed)))
	sum.files = append(sum.files, configPath, fmt.Sprintf("%s (armed: %v)", policyPath, state.armed))

	// 10. Stub any referenced secret env var with the placeholder so the
	//     operator has a discoverable slot and systemd's EnvironmentFile never
	//     fails loudly; an existing real value is preserved (idempotent).
	envPath := filepath.Join(configDir, envFileName)
	if names := neededEnvVars(state); len(names) > 0 {
		touched, err := ensureEnvPlaceholders(configDir, names)
		if err != nil {
			return err
		}
		if touched {
			p.println(st.ok("wrote " + envPath + " (chmod 600, placeholder env references — fill in the real secrets)"))
			p.printf("    Secrets referenced: %s — set them in %s (or via systemd credentials).\n",
				strings.Join(names, ", "), envPath)
		} else {
			p.println(st.ok("kept " + envPath + " (existing secrets preserved)"))
		}
		sum.files = append(sum.files, envPath+" (mode 0600 — secret tokens live here, never in config.yaml)")
	}

	// 11. rules.d drop-in dir + WordPress tuning template — same helpers as
	//     the wizard.
	rulesDir := filepath.Join(configDir, "rules.d")
	if err := ensureRulesDir(rulesDir); err != nil {
		return err
	}
	sum.files = append(sum.files, rulesDir+" (drop-in rule customizations — merged over the built-in rules)")
	if state.hasWordPress {
		wrote, err := writeWordPressDropin(state.wpRulesPath)
		if err != nil {
			return err
		}
		if wrote {
			p.println(st.ok("wrote " + state.wpRulesPath + " (commented tuning template)"))
			sum.files = append(sum.files, state.wpRulesPath)
		}
	}

	sum.skipped = append(sum.skipped,
		"systemd services — not started (non-interactive writes config only; start with systemctl or 'ezyshield run')")

	if p.err != nil {
		return fmt.Errorf("writing output: %w", p.err)
	}

	// 12. Summary: machine-readable JSON to stdout, or the wizard's own text
	//     summary + next steps (config-only variant).
	if jsonOutput {
		return writeInitJSONSummary(cmd.OutOrStdout(), state, sum, configDir)
	}
	renderInitSummary(p, st, state, sum, -1, configDir)
	return p.err
}

// loadInitAnswers reads and strictly decodes the answers file. An empty path
// (flags-only run) or an empty file yields a zero-value initAnswers. Unknown
// keys are rejected with a message that names the offending field.
func loadInitAnswers(path string) (*initAnswers, error) {
	a := &initAnswers{}
	if path == "" {
		return a, nil
	}
	f, err := os.Open(path) //nolint:gosec // operator-supplied answers path; read-only
	if err != nil {
		return nil, fmt.Errorf("opening answers file %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only close
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true) // unknown keys => error (typo protection, issue #231)
	if err := dec.Decode(a); err != nil {
		if errors.Is(err, io.EOF) {
			return a, nil // empty file == flags-only
		}
		return nil, fmt.Errorf("parsing answers file %s: %w", path, err)
	}
	return a, nil
}

// applyFlagOverrides layers CLI flags on top of the parsed answers. Only flags
// the operator actually set (Changed) override; an unset flag never clobbers a
// file value. No secret VALUE flag exists — --ai-key-env carries a NAME only.
func applyFlagOverrides(cmd *cobra.Command, a *initAnswers) {
	fs := cmd.Flags()
	if fs.Changed("monitor-ssh") {
		v, _ := fs.GetBool("monitor-ssh")
		a.Collectors.SSH = &v
	}
	if fs.Changed("admin-ips") {
		v, _ := fs.GetString("admin-ips")
		// splitIPs returns a non-nil slice even when empty, so --admin-ips ""
		// is an explicit "no admin IPs", distinct from omitting the flag.
		a.Allowlist.AdminIPs = splitIPs(v)
	}
	if fs.Changed("enable-ai") {
		v, _ := fs.GetBool("enable-ai")
		a.AI.Enabled = v
	}
	if fs.Changed("ai-provider") {
		v, _ := fs.GetString("ai-provider")
		a.AI.Provider = v
	}
	if fs.Changed("ai-model") {
		v, _ := fs.GetString("ai-model")
		a.AI.Model = v
	}
	if fs.Changed("ai-key-env") {
		v, _ := fs.GetString("ai-key-env")
		a.AI.APIKeyEnv = v
	}
}

// rejectLiteralSecrets fails closed on any credential offered as a literal
// value — in the answers file (api_key / api_token) or, indirectly, as an
// *_env value that looks like a key (caught later by ValidateEnvVarName). The
// message explains WHY (shell-history / process-list leakage, Hard Rule 3) and
// where the value belongs, and never echoes more than a redacted fingerprint.
func rejectLiteralSecrets(a *initAnswers) error {
	if a.AI.APIKey != "" {
		return fmt.Errorf(
			"ai.api_key is not accepted (got %s): the API key must never appear in the answers file or a flag — "+
				"it would leak into shell history and process lists; put it in %s and reference the variable NAME via ai.api_key_env",
			config.RedactSecret(a.AI.APIKey), envFileName)
	}
	for i, cf := range a.Enforce.Cloudflare {
		if cf.APIToken != "" {
			return fmt.Errorf(
				"enforce.cloudflare[%d].api_token is not accepted (got %s): the token must never appear in the answers file or a flag — "+
					"it would leak into shell history and process lists; put it in %s and reference the variable NAME via api_token_env",
				i, config.RedactSecret(cf.APIToken), envFileName)
		}
	}
	return nil
}

// validateAnswers collects EVERY problem in one pass so the operator sees all
// missing/invalid answers at once instead of one-per-run. Deep format checks
// that the strict config loader already owns (parser names, list_name shape,
// account-name charset) are left to the render+validate step; this pass covers
// the answer-level requiredness the loader cannot see (env-name fields,
// enabled toggles) plus the common "you forgot X" cases.
func validateAnswers(a *initAnswers) []string {
	var problems []string

	// AI.
	if a.AI.Enabled {
		switch {
		case a.AI.Provider == "":
			problems = append(problems, "ai.provider is required when ai.enabled is true (anthropic|openai|ollama)")
		case !knownAIProvider(a.AI.Provider):
			problems = append(problems,
				fmt.Sprintf("ai.provider %q is unknown (must be anthropic|openai|ollama)", a.AI.Provider))
		}
		if a.AI.APIKeyEnv != "" {
			if err := config.ValidateEnvVarName(a.AI.APIKeyEnv); err != nil {
				problems = append(problems, "ai.api_key_env: "+err.Error())
			}
		}
	}

	// Web collectors.
	for i, w := range a.Collectors.Web {
		switch w.Kind {
		case "file":
			if w.Path == "" {
				problems = append(problems, fmt.Sprintf("collectors.web[%d]: kind 'file' requires 'path'", i))
			}
		case "docker":
			if w.Container == "" {
				problems = append(problems, fmt.Sprintf("collectors.web[%d]: kind 'docker' requires 'container'", i))
			}
		case "":
			problems = append(problems, fmt.Sprintf("collectors.web[%d]: 'kind' is required (file|docker)", i))
		default:
			problems = append(problems, fmt.Sprintf("collectors.web[%d]: invalid kind %q (must be file|docker)", i, w.Kind))
		}
		if w.Parser == "" {
			problems = append(problems,
				fmt.Sprintf("collectors.web[%d]: 'parser' is required (nginx|apache|apache-error|traefik|caddy)", i))
		}
	}

	// Admin IPs.
	for i, ip := range a.Allowlist.AdminIPs {
		if !validIPOrPrefix(ip) {
			problems = append(problems,
				fmt.Sprintf("allowlist.admin_ips[%d]: %q is not a valid IP or CIDR", i, ip))
		}
	}

	// Cloudflare accounts.
	seen := map[string]bool{}
	multi := len(a.Enforce.Cloudflare) > 1
	for i, cf := range a.Enforce.Cloudflare {
		if cf.APITokenEnv != "" {
			if err := config.ValidateEnvVarName(cf.APITokenEnv); err != nil {
				problems = append(problems, fmt.Sprintf("enforce.cloudflare[%d].api_token_env: %v", i, err))
			}
		}
		mode := cf.Mode
		if mode == "" {
			mode = "lists"
		}
		switch mode {
		case "lists":
			if cf.AccountID == "" {
				problems = append(problems,
					fmt.Sprintf("enforce.cloudflare[%d]: 'account_id' is required when mode is 'lists'", i))
			}
		case "rulesets":
			if len(cf.ZoneIDs) == 0 {
				problems = append(problems,
					fmt.Sprintf("enforce.cloudflare[%d]: 'zone_ids' is required when mode is 'rulesets'", i))
			}
		default:
			problems = append(problems,
				fmt.Sprintf("enforce.cloudflare[%d]: invalid mode %q (must be lists|rulesets)", i, cf.Mode))
		}
		if multi {
			switch {
			case cf.Name == "":
				problems = append(problems,
					fmt.Sprintf("enforce.cloudflare[%d]: 'name' is required when more than one cloudflare account is configured", i))
			case seen[cf.Name]:
				problems = append(problems, fmt.Sprintf("enforce.cloudflare[%d]: duplicate name %q", i, cf.Name))
			}
			seen[cf.Name] = true
		}
	}

	return problems
}

// applyAnswers fills state from the validated answers, reusing the wizard's
// own helpers (confirmWebServerCollectors, cfEnvVarForName, the AI/CF tables)
// so the generated config is identical to the interactive one. It sets every
// field askQuestions would set — and forces armed false (Hard Rule 1).
func applyAnswers(state *wizardState, a *initAnswers) {
	// SSH collector (default on, matching the wizard).
	monitorSSH := true
	if a.Collectors.SSH != nil {
		monitorSSH = *a.Collectors.SSH
	}
	state.monitorSSH = monitorSSH && state.sshUnit != ""

	// Web collectors: explicit answers replace detection; otherwise accept
	// every detected server with its default log path (the --yes outcome).
	if a.Collectors.Web != nil {
		state.webCollectors = nil
		for _, w := range a.Collectors.Web {
			wc := webServerCollector{Kind: w.Kind, Parser: w.Parser}
			switch w.Kind {
			case "file":
				wc.Path = w.Path
			case "docker":
				wc.Container = w.Container
			}
			state.webCollectors = append(state.webCollectors, wc)
		}
	} else {
		state.webCollectors = acceptDetectedWebCollectors(state.webServers)
	}

	// Admin allowlist: explicit only. Unlike --yes we do NOT auto-add a
	// detected IP: at golden-image build time that IP is the builder, not the
	// production host, and baking it into admin_cidrs would be a silent
	// footgun (allowlist always wins). Omitted => empty (+ warning).
	if a.Allowlist.AdminIPs != nil {
		state.adminIPs = append([]string(nil), a.Allowlist.AdminIPs...)
	}

	// AI provider (secrets never flow through answers — aiToken stays empty,
	// so the .env placeholder path applies exactly as in the wizard).
	if a.AI.Enabled {
		state.enableAI = true
		state.aiProvider = a.AI.Provider
		state.aiModel = a.AI.Model
		if state.aiModel == "" {
			state.aiModel = aiProviderDefaultModel[a.AI.Provider]
		}
		state.aiKeyEnvVar = a.AI.APIKeyEnv
		if state.aiKeyEnvVar == "" {
			state.aiKeyEnvVar = aiProviderKeyName[a.AI.Provider]
		}
		state.aiToken = ""
	}

	// Cloudflare edge enforcer.
	state.cdn = &cdnStep{}
	if len(a.Enforce.Cloudflare) > 0 {
		state.cdn.cfEnabled = true
		for _, cf := range a.Enforce.Cloudflare {
			mode := cf.Mode
			if mode == "" {
				mode = "lists"
			}
			// Default action to "block", matching the interactive CF subflow
			// (which always writes an explicit action) so the generated config
			// and summary read identically whether wizard- or answers-driven.
			action := cf.Action
			if action == "" {
				action = "block"
			}
			tokenEnv := cf.APITokenEnv
			if tokenEnv == "" {
				tokenEnv = cfEnvVarForName(cf.Name)
			}
			state.cdn.cfAccounts = append(state.cdn.cfAccounts, cfAccountSetup{
				cfg: config.CloudflareCfg{
					Name:      cf.Name,
					APIToken:  config.SecretRef("env:" + tokenEnv),
					Mode:      mode,
					Action:    action,
					AccountID: cf.AccountID,
					ListName:  cf.ListName,
					ZoneIDs:   cf.ZoneIDs,
				},
				tokenEnvVar: tokenEnv,
			})
		}
	}

	// Invariant: non-interactive init is always dry-run (Hard Rule 1). There
	// is deliberately no answer or flag to arm — the operator arms explicitly
	// after observing clean dry-run output.
	state.armed = false
}

// neededEnvVars returns the env var NAMES the generated config references and
// that therefore need a value (real, or the placeholder stub). Ollama has no
// key, so aiKeyEnvVar is empty and contributes nothing.
func neededEnvVars(state *wizardState) []string {
	var names []string
	if state.enableAI && state.aiKeyEnvVar != "" {
		names = append(names, state.aiKeyEnvVar)
	}
	if state.cdn != nil && state.cdn.cfEnabled {
		for _, acct := range state.cdn.cfAccounts {
			if acct.tokenEnvVar != "" {
				names = append(names, acct.tokenEnvVar)
			}
		}
	}
	return names
}

// ensureEnvPlaceholders merges a placeholder line for each missing env var
// into <configDir>/.env, preserving comments and any existing real value
// (idempotent re-run). Returns touched=false when nothing changed. Mode +
// ownership match the wizard's .env writes: 0600 root:ezyshield.
func ensureEnvPlaceholders(configDir string, names []string) (touched bool, err error) {
	envPath := filepath.Join(configDir, envFileName)
	lines, err := loadEnvFileLines(envPath)
	if err != nil {
		return false, err
	}
	changed := false
	for _, name := range names {
		if name == "" {
			continue
		}
		if v, ok := envValueFromLines(lines, name); ok {
			// Preserve a real secret; leave an existing placeholder untouched.
			if v != "" && v != envAPIKeyPlaceholder {
				continue
			}
			if v == envAPIKeyPlaceholder {
				continue
			}
		}
		lines = upsertEnvLine(lines, name, envAPIKeyPlaceholder)
		changed = true
	}
	if !changed {
		return false, nil
	}
	body := renderEnvFile(lines)
	if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
		return false, fmt.Errorf("writing %s: %w", envPath, err)
	}
	if err := applyDaemonOwnership(envPath, 0o600); err != nil {
		return false, fmt.Errorf("set ownership on %s: %w", envPath, err)
	}
	return true, nil
}

// envValueFromLines returns the trimmed value for name from parsed env lines.
func envValueFromLines(lines []envLine, name string) (string, bool) {
	for _, l := range lines {
		if l.key == name {
			return strings.TrimSpace(l.value), true
		}
	}
	return "", false
}

// commitTwoFilesAtomic stages both files to temp files in their target
// directory, then renames both into place. Renders are already validated by
// the caller, so the only failures here are I/O; staging both before renaming
// either means a failure leaves neither destination half-written.
func commitTwoFilesAtomic(pathA string, dataA []byte, pathB string, dataB []byte, perm os.FileMode) error {
	tmpA, err := stageTempFile(pathA, dataA, perm)
	if err != nil {
		return err
	}
	tmpB, err := stageTempFile(pathB, dataB, perm)
	if err != nil {
		_ = os.Remove(tmpA)
		return err
	}
	if err := os.Rename(tmpA, pathA); err != nil {
		_ = os.Remove(tmpA)
		_ = os.Remove(tmpB)
		return fmt.Errorf("replacing %s: %w", pathA, err)
	}
	if err := os.Rename(tmpB, pathB); err != nil {
		_ = os.Remove(tmpB)
		return fmt.Errorf("replacing %s: %w", pathB, err)
	}
	return nil
}

// stageTempFile writes data to a fresh temp file in path's directory with perm
// and returns its name for a subsequent rename. On any error the temp file is
// removed and the error returned.
func stageTempFile(path string, data []byte, perm os.FileMode) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file for %s: %w", path, err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("writing %s: %w", name, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("chmod %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("closing %s: %w", name, err)
	}
	return name, nil
}

// initJSONSummary is the machine-readable form of the final summary (--json).
// Field order and names are a stable contract for scripted callers.
type initJSONSummary struct {
	Mode       string   `json:"mode"`
	Armed      bool     `json:"armed"`
	ConfigDir  string   `json:"config_dir"`
	Configured []string `json:"configured"`
	Skipped    []string `json:"skipped"`
	Files      []string `json:"files"`
	NextSteps  []string `json:"next_steps"`
}

// writeInitJSONSummary emits the JSON summary to w. It mirrors the fields
// renderInitSummary prints in config-only mode (detections < 0).
func writeInitJSONSummary(w io.Writer, state *wizardState, sum *initSummary, configDir string) error {
	policyPath := filepath.Join(configDir, "policy.yaml")
	steps := []string{
		fmt.Sprintf("%s doctor — verify the configuration", progName),
		fmt.Sprintf("%s run — start in the foreground and observe", progName),
		fmt.Sprintf("%s watch — see detections live", progName),
	}
	if !state.armed {
		steps = append(steps,
			fmt.Sprintf("set armed: true in %s when confident (after 24h+ of clean dry-run)", policyPath))
	}
	return writeJSON(w, initJSONSummary{
		Mode:       modeLabel(state.armed),
		Armed:      state.armed,
		ConfigDir:  configDir,
		Configured: nonNil(sum.configured),
		Skipped:    nonNil(sum.skipped),
		Files:      nonNil(sum.files),
		NextSteps:  steps,
	})
}

// nonNil returns s, or an empty slice when s is nil, so JSON arrays render as
// [] rather than null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// acceptDetectedWebCollectors converts every detected web server into a
// collector with its default settings — the exact outcome
// confirmWebServerCollectors produces under --yes (askBool yields its default
// true, ask returns the default log path). Reused, not reimplemented.
func acceptDetectedWebCollectors(servers []detectedWebServer) []webServerCollector {
	ask := func(_, def string) string { return def }
	askBool := func(_ string, def bool) bool { return def }
	return confirmWebServerCollectors(ask, askBool, servers)
}

// knownAIProvider reports whether name is one of the supported AI providers.
func knownAIProvider(name string) bool {
	_, ok := aiProviderKeyName[name]
	return ok
}

// validIPOrPrefix reports whether s parses as a bare IP or a CIDR prefix.
func validIPOrPrefix(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	return false
}
