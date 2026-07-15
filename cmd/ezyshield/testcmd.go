package main

// The `test` command group — connectivity tests per component, following the
// same `<group> <kind> <name>` registry pattern the `config` group uses
// (frozen CLI taxonomy, issue #104). `test enforcer <name>` and
// `test notifier <name>` run exactly the flows the legacy
// `test-enforce`/`test-notify` verbs ran; those verbs remain as hidden
// deprecated aliases until 1.0.

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// componentTest runs the connectivity test for one component name of a kind.
// Implementations live in testenforce.go / testnotify.go.
type componentTest func(cmd *cobra.Command, configDir, name string) error

// componentTests is the kind → name → test registry, mirroring
// componentWizards (configwizard.go). New kinds/names plug in here without
// further CLI changes.
var componentTests = map[string]map[string]componentTest{
	"enforcer": {
		"cloudflare": runTestEnforce,
		"nftables":   runTestEnforce,
		"all":        runTestEnforce,
	},
	"notifier": {
		"telegram": runTestNotify,
		"email":    runTestNotify,
		"all":      runTestNotify,
	},
}

// lookupComponentTest resolves kind+name against the registry. Unknown
// values produce errors that list what IS available, so a typo never leaves
// the operator guessing.
func lookupComponentTest(kind, name string) (componentTest, error) {
	byName, ok := componentTests[kind]
	if !ok {
		return nil, fmt.Errorf("unknown component kind %q (available: %s)",
			kind, strings.Join(sortedWizardKeys(componentTests), ", "))
	}
	run, ok := byName[name]
	if !ok {
		return nil, fmt.Errorf("unknown %s %q (available: %s)",
			kind, name, strings.Join(sortedWizardKeys(byName), ", "))
	}
	return run, nil
}

func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test connectivity of configured components",
		Long: `Run connectivity tests against configured components.

Subcommands:
  enforcer   validate an enforcer backend's tokens and permissions
  notifier   send a synthetic alert to a notification channel`,
	}
	cmd.AddCommand(
		newTestKindCmd("enforcer",
			"Test enforcer backend connectivity and permissions",
			`Test the configuration and permissions of an enforcer backend.

The command loads the enforce configuration from --config-dir/config.yaml,
validates API tokens and permissions, and reports what's working and what's
missing. Exit code is 0 if all checks pass, 1 if any check fails.`),
		newTestKindCmd("notifier",
			"Send a test notification to a configured channel",
			`Send a synthetic alert to verify that a notification channel is
correctly configured.

The command loads notify configuration from --config-dir/config.yaml,
resolves secrets from the environment variables declared in
bot_token/password, and sends a test ban notification. Exit code is
non-zero on failure.`),
	)
	return cmd
}

// newTestKindCmd builds the `test <kind> <name>` command for one component
// kind, backed by the shared registry.
func newTestKindCmd(kind, short, long string) *cobra.Command {
	var configDir string

	cmd := &cobra.Command{
		Use:   kind + " <name>",
		Short: short,
		Long: long + "\n\nAvailable names: " +
			strings.Join(sortedWizardKeys(componentTests[kind]), ", "),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			run, err := lookupComponentTest(kind, args[0])
			if err != nil {
				return err
			}
			return run(cmd, configDir, args[0])
		},
	}
	cmd.Flags().StringVar(&configDir, "config-dir", defaultConfigDir,
		"directory containing config.yaml")
	return cmd
}

// newDeprecatedTestAliasCmd keeps a pre-taxonomy verb (`test-enforce`,
// `test-notify`) working as a hidden alias of `test <kind> <name>`: same
// flags, same behavior, plus a one-line migration notice on stderr.
// Removal at 1.0.
func newDeprecatedTestAliasCmd(oldName, kind string, run componentTest) *cobra.Command {
	var configDir string

	cmd := &cobra.Command{
		Use:   oldName + " <name>",
		Short: fmt.Sprintf("[DEPRECATED] Use 'test %s <name>' instead", kind),
		Long: fmt.Sprintf(`[DEPRECATED] '%s' has moved to 'test %s <name>' and will be
removed in 1.0. Behavior is identical.`, oldName, kind),
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"warning: '%s' is deprecated and will be removed in 1.0 — use '%s test %s %s' instead\n",
				oldName, cmd.Root().Name(), kind, args[0])
			return run(cmd, configDir, args[0])
		},
	}
	cmd.Flags().StringVar(&configDir, "config-dir", defaultConfigDir,
		"directory containing config.yaml")
	return cmd
}
