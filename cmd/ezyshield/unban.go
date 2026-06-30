package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func newUnbanCmd() *cobra.Command {
	var socketPath string

	cmd := &cobra.Command{
		Use:   "unban <ip|cidr>",
		Short: "Remove an IP or CIDR ban via the running daemon",
		Long: `Send an unban request to the daemon for the given IP address or CIDR.

A bare address removes the single ban for that IP. A CIDR removes every active
ban whose IP falls within the range. The operation is logged to the audit log
in either case.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTarget(args[0]); err != nil {
				return err
			}
			return runUnban(cmd, socketPath, args[0])
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")

	return cmd
}

func runUnban(cmd *cobra.Command, socketPath, target string) error {
	resp, err := daemonRPC(context.Background(), socketPath,
		daemon.SocketRequest{Verb: "unban", IP: target})
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), resp)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "unbanned %s\n", target)
	return err
}
