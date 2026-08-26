// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func newAllowCmd() *cobra.Command {
	var (
		socketPath string
		forDur     string
		until      string
		reason     string
	)

	cmd := &cobra.Command{
		Use:   "allow <ip|cidr>",
		Short: "Add an IP or CIDR to the daemon's allowlist",
		Long: `Add an IP or CIDR to the daemon's persistent allowlist.

Without --for or --until the entry is permanent (until explicitly removed).
Use --for for a duration ("24h", "7d", "30d") or --until for an absolute
ISO 8601 datetime ("2026-07-15" or "2026-07-15T18:00:00"). Expired entries
are auto-removed by the daemon's expiry sweep.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if forDur != "" && until != "" {
				return fmt.Errorf("--for and --until are mutually exclusive")
			}
			if err := validateTarget(args[0]); err != nil {
				return err
			}
			return runAllow(cmd, socketPath, args[0], forDur, until, reason)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().StringVar(&forDur, "for", "",
		"duration before the allow expires (e.g. \"24h\", \"7d\", \"30d\")")
	cmd.Flags().StringVar(&until, "until", "",
		"absolute expiry, ISO 8601 (e.g. \"2026-07-15\" or \"2026-07-15T18:00:00\")")
	cmd.Flags().StringVar(&reason, "reason", "",
		"free-text note, shown in list output and the audit log")

	return cmd
}

func runAllow(cmd *cobra.Command, socketPath, target, forDur, until, reason string) error {
	resp, err := daemonRPC(cmd.Context(), socketPath,
		daemon.SocketRequest{
			Verb:   "allow",
			IP:     target,
			For:    forDur,
			Until:  until,
			Reason: reason,
		})
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), resp)
	}
	suffix := ""
	switch {
	case forDur != "":
		suffix = " (expires after " + forDur + ")"
	case until != "":
		suffix = " (until " + until + ")"
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s added to allowlist%s\n", target, suffix)
	return err
}

func newUnallowCmd() *cobra.Command {
	var (
		socketPath string
		reason     string
	)

	cmd := &cobra.Command{
		Use:   "unallow <ip|cidr>",
		Short: "Remove an IP or CIDR from the daemon's runtime allowlist",
		Long: `Remove an entry previously added with "allow" from the daemon's
persistent runtime allowlist.

The target must match the stored entry exactly (the same IP or CIDR that was
allowed). Entries from the static config allowlist cannot be removed at
runtime — edit the config and restart the daemon instead.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateTarget(args[0]); err != nil {
				return err
			}
			return runUnallow(cmd, socketPath, args[0], reason)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().StringVar(&reason, "reason", "",
		"free-text note, recorded in the audit log")

	return cmd
}

func runUnallow(cmd *cobra.Command, socketPath, target, reason string) error {
	resp, err := daemonRPC(cmd.Context(), socketPath,
		daemon.SocketRequest{
			Verb:   "unallow",
			IP:     target,
			Reason: reason,
		})
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), resp)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s removed from allowlist\n", target)
	return err
}
