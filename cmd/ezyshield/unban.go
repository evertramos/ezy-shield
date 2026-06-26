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
		Use:   "unban <ip>",
		Short: "Remove an IP ban via the running daemon",
		Long: `Send an unban request to the daemon for the given IP address.

The IP is removed from the active ban set in the store and from nftables
(if armed). The operation is logged to the audit log.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUnban(cmd, socketPath, args[0])
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")

	return cmd
}

func runUnban(cmd *cobra.Command, socketPath, ip string) error {
	resp, err := daemonRPC(context.Background(), socketPath,
		daemon.SocketRequest{Verb: "unban", IP: ip})
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), resp)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "unbanned %s\n", ip)
	return err
}
