package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), map[string]string{
					"version":    version,
					"commit":     commit,
					"build_date": buildDate,
				})
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %s (commit: %s, built: %s)\n",
				cmd.Root().Name(), version, commit, buildDate)
			return err
		},
	}
}
