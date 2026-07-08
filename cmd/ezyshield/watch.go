package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// newWatchCmdDeprecated returns the deprecated 'watch' command that delegates to 'run'.
// Kept for backward compatibility; prints a warning and delegates to the new 'run' command.
func newWatchCmdDeprecated() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "[DEPRECATED] Use 'run' instead",
		Long: `[DEPRECATED] The 'watch' command has been renamed to 'run' for clarity.
Use 'ezyshield run' to start the daemon.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stderr, "warning: 'watch' is deprecated — use 'run' instead\n")
			// Delegate to the run command
			return newRunCmd().RunE(cmd, args)
		},
		Hidden: true,
	}
	return cmd
}
