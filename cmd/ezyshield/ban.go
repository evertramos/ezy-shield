package main

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func newBanCmd() *cobra.Command {
	var (
		socketPath string
		ttl        string
		reason     string
	)

	cmd := &cobra.Command{
		Use:   "ban <ip|cidr>",
		Short: "Manually ban an IP or CIDR via the running daemon",
		Long: `Send a ban request to the daemon for the given IP address or CIDR.

A bare address (e.g. 1.2.3.4) is treated as a host prefix (/32 or /128).
A CIDR (e.g. 203.0.113.0/24) bans the entire range.

If the daemon is in dry-run mode (armed=false in policy.yaml) the command is
recorded in the audit log but no firewall rule is written.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTarget(args[0]); err != nil {
				return err
			}
			return runBan(cmd, socketPath, args[0], ttl, reason)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().StringVar(&ttl, "ttl", "",
		"ban duration, e.g. \"5m\", \"24h\", \"7d\" (empty = policy strike table)")
	cmd.Flags().StringVar(&reason, "reason", "",
		"free-text note, shown in audit log")

	return cmd
}

func runBan(cmd *cobra.Command, socketPath, target, ttl, reason string) error {
	resp, err := daemonRPC(context.Background(), socketPath,
		// Peer forwards this session's SSH client IP so the daemon's
		// manual-ban anti-lockout guard can protect it (issue #211) — the
		// daemon has no SSH_CLIENT of its own under systemd.
		daemon.SocketRequest{Verb: "ban", IP: target, TTL: ttl, Reason: reason, Peer: sshClientPeer()})
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), resp)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "ban queued for %s\n", target)
	return err
}

// validateTarget rejects inputs that are neither a valid IP nor a valid CIDR
// before they reach the daemon, so the user gets a clear message client-side.
func validateTarget(s string) error {
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	return fmt.Errorf("invalid ip or cidr: %q", s)
}
