package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func newBanCmd() *cobra.Command {
	var (
		socketPath string
		ttl        string
	)

	cmd := &cobra.Command{
		Use:   "ban <ip>",
		Short: "Manually ban an IP via the running daemon",
		Long: `Send a ban request to the daemon for the given IP address.

If the daemon is in dry-run mode (armed=false in policy.yaml) the command is
recorded in the audit log but no firewall rule is written.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBan(cmd, socketPath, args[0], ttl)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().StringVar(&ttl, "ttl", "",
		"ban duration, e.g. \"5m\", \"24h\" (empty = policy strike table)")

	return cmd
}

func runBan(cmd *cobra.Command, socketPath, ip, ttl string) error {
	resp, err := daemonRPC(context.Background(), socketPath,
		daemon.SocketRequest{Verb: "ban", IP: ip, TTL: ttl})
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), resp)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "ban queued for %s\n", ip)
	return err
}
