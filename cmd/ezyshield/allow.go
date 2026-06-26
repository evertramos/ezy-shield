package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func newAllowCmd() *cobra.Command {
	var socketPath string

	cmd := &cobra.Command{
		Use:   "allow <ip>",
		Short: "Add an IP to the daemon's runtime allowlist",
		Long: `Add an IP to the running daemon's in-memory allowlist.

The entry takes effect immediately: the pipeline will skip any future ban
decisions for this IP until the daemon restarts.  For permanent allowlist
entries add the IP to policy.yaml instead.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAllow(cmd, socketPath, args[0])
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")

	return cmd
}

func runAllow(cmd *cobra.Command, socketPath, ip string) error {
	resp, err := daemonRPC(context.Background(), socketPath,
		daemon.SocketRequest{Verb: "allow", IP: ip})
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), resp)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s added to runtime allowlist\n", ip)
	return err
}
