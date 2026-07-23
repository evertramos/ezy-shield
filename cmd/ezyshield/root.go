package main

import "github.com/spf13/cobra"

// progName is the user-facing invocation name used in help text and hints.
// Single definition site (see AGENTS.md "CLI naming"): the root command and
// every printed hint derive from it, so the future `ezy shield` dispatcher
// renames the CLI by changing this one line.
const progName = "ezyshield"

// jsonOutput is set by the --json persistent flag and read by all subcommands.
var jsonOutput bool

// noColor is set by the --no-color persistent flag; colorEnabled honors it
// alongside the NO_COLOR environment variable and TTY detection.
var noColor bool

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   progName,
		Short: "EzyShield — Linux security daemon (ezy shield)",
		Long: `EzyShield is a CLI-first Linux security tool.

It detects malicious IPs from logs, escalates bans by strike count,
and enforces blocks locally (nftables) and at the edge (Cloudflare/Bunny/AWS).

Commands read as:  ` + progName + ` VERB   (equivalent to: ezy shield VERB)`,
		// Wires up `ezyshield --version` (used by the self-update verifier
		// to confirm a freshly downloaded binary actually runs).
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output results as JSON")
	root.PersistentFlags().BoolVar(&noColor, "no-color", false,
		"disable colored output (the NO_COLOR env var is also honored)")

	root.AddCommand(
		newVersionCmd(),
		newInitCmd(),
		newStatusCmd(),
		newDoctorCmd(),
		newConfigCmd(),
		newValidateCmd(),
		newCompletionCmd(root),
		newGenDocsCmd(root),
		newTestCmd(),
		// Pre-taxonomy verbs kept as hidden deprecated aliases until 1.0.
		newDeprecatedTestAliasCmd("test-notify", "notifier", runTestNotify),
		newDeprecatedTestAliasCmd("test-enforce", "enforcer", runTestEnforce),
		newRunCmd(),
		newArmCmd(),
		newDisarmCmd(),
		newWatchCmd(),
		newBanCmd(),
		newUnbanCmd(),
		newListCmd(),
		newReportCmd(),
		newAllowCmd(),
		newScanCmd(),
		newUpdateCmd(),
		newDashboardCmd(),
	)

	return root
}
