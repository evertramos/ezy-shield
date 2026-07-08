package main

import "github.com/spf13/cobra"

// jsonOutput is set by the --json persistent flag and read by all subcommands.
var jsonOutput bool

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "ezyshield",
		Short: "EzyShield — Linux security daemon (ezy shield)",
		Long: `EzyShield is a CLI-first Linux security tool.

It detects malicious IPs from logs, escalates bans by strike count,
and enforces blocks locally (nftables) and at the edge (Cloudflare/Bunny/AWS).

Commands read as:  ezyshield <verb>   (equivalent to: ezy shield <verb>)`,
		// Wires up `ezyshield --version` (used by the self-update verifier
		// to confirm a freshly downloaded binary actually runs).
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output results as JSON")

	root.AddCommand(
		newVersionCmd(),
		newInitCmd(),
		newStatusCmd(),
		newDoctorCmd(),
		newValidateCmd(),
		newCompletionCmd(root),
		newTestNotifyCmd(),
		newTestEnforceCmd(),
		newRunCmd(),
		newWatchCmd(),
		newBanCmd(),
		newUnbanCmd(),
		newListCmd(),
		newAllowCmd(),
		newScanCmd(),
		newUpdateCmd(),
		newDashboardCmd(),
	)

	return root
}
