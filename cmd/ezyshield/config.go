package main

// The `config` command group — occasional-management verbs per the frozen CLI
// taxonomy (config/test as noun groups, short verbs for daily operation).
// This cut ships `show` and `validate`; the per-component wizards
// (`config enforcer|notifier|ai|collector <name>`) land in a follow-up that
// extracts the init sub-flows behind a shared component registry.

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/evertramos/ezy-shield/internal/config"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate configuration",
		Long: `Inspect and validate EzyShield configuration files.

Subcommands:
  show      render the effective configuration (secrets redacted)
  validate  check config.yaml and policy.yaml without starting the daemon
  enforcer  interactive wizard for one enforcer (e.g. cloudflare)`,
	}
	cmd.AddCommand(
		newConfigShowCmd(),
		newValidateCmd(),
		newConfigComponentCmd("enforcer", "Configure an enforcer interactively"),
	)
	return cmd
}

func newConfigShowCmd() *cobra.Command {
	var (
		configPath = defaultConfigDir + "/config.yaml"
		policyPath = defaultConfigDir + "/policy.yaml"
	)

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the effective configuration (secrets redacted)",
		Long: `Render the effective configuration — after parsing, strict validation,
and defaults — exactly as the daemon would run with it.

Output is YAML by default, or JSON with --json. Secret values never
appear: credential fields hold env:VARNAME references by design, and
webhook header values (which may carry raw tokens) are replaced with
"<redacted>".

Exit codes:
  0  rendered
  1  configuration invalid
  2  file not found / unreadable`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			code := runConfigShow(cmd.OutOrStdout(), cmd.ErrOrStderr(),
				configPath, policyPath, jsonOutput)
			if code != validateExitOK {
				os.Exit(code)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", configPath, "path to config.yaml")
	cmd.Flags().StringVar(&policyPath, "policy", policyPath, "path to policy.yaml")
	return cmd
}

// runConfigShow loads both files, redacts, and renders to w (errors go to
// ew). Split from the cobra wiring so tests can drive it without os.Exit.
// Exit codes mirror runValidate: 0 OK, 1 invalid, 2 not found/unreadable.
func runConfigShow(w, ew io.Writer, configPath, policyPath string, asJSON bool) int {
	for _, path := range []string{configPath, policyPath} {
		switch statRegularFile(path) {
		case fileMissing:
			writef(ew, "ERROR: file not found: %s\n", path)
			return validateExitNotFound
		case fileUnreadable:
			writef(ew, "ERROR: file not readable: %s\n", path)
			return validateExitNotFound
		}
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		writef(ew, "ERROR: %v\n", err)
		return validateExitError
	}
	pol, err := config.LoadPolicy(policyPath)
	if err != nil {
		writef(ew, "ERROR: %v\n", err)
		return validateExitError
	}

	if err := renderShow(w, cfg.Redacted(), pol, configPath, policyPath, asJSON); err != nil {
		writef(ew, "ERROR: %v\n", err)
		return validateExitError
	}
	return validateExitOK
}

// renderShow emits the redacted effective view: two YAML documents (config,
// then policy) separated by "---", or one JSON object with "config" and
// "policy" keys. JSON reuses the YAML field names by round-tripping the
// structs through yaml.Marshal into plain maps — the config structs carry
// yaml tags only, and duplicating them as json tags would invite drift.
func renderShow(w io.Writer, cfg *config.Config, pol *config.Policy, configPath, policyPath string, asJSON bool) error {
	if asJSON {
		cfgMap, err := yamlToMap(cfg)
		if err != nil {
			return err
		}
		polMap, err := yamlToMap(pol)
		if err != nil {
			return err
		}
		return writeJSON(w, map[string]any{"config": cfgMap, "policy": polMap})
	}

	cfgYAML, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("rendering config: %w", err)
	}
	polYAML, err := yaml.Marshal(pol)
	if err != nil {
		return fmt.Errorf("rendering policy: %w", err)
	}
	writef(w, "# effective config — %s (secrets redacted)\n%s", configPath, cfgYAML)
	writef(w, "---\n# effective policy — %s\n%s", policyPath, polYAML)
	return nil
}

// yamlToMap converts v to a generic map so the JSON encoder emits the same
// snake_case field names the YAML form uses.
func yamlToMap(v any) (map[string]any, error) {
	raw, err := yaml.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("rendering: %w", err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("rendering: %w", err)
	}
	return m, nil
}
