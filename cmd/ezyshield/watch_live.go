package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func newWatchCmd() *cobra.Command {
	var (
		socketPath string
		follow     bool
	)

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch live bans from the running daemon",
		Long: `Connect to the EzyShield daemon and display live ban activity.

Shows the current list of active bans in real time. With --follow, continuously
refreshes to show changes (default: one-shot).

The daemon must be running (start with 'sudo systemctl start ezyshield' or
'ezyshield run').`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWatch(cmd, socketPath, follow)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false,
		"continuously refresh to show live updates")

	return cmd
}

func runWatch(cmd *cobra.Command, socketPath string, follow bool) error {
	ctx := context.Background()

	// Verify the daemon is running by attempting a connection
	if err := verifyDaemonRunning(ctx, socketPath); err != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), //nolint:errcheck
			"EzyShield daemon is not running — start with: sudo systemctl start ezyshield\n")
		return err
	}

	if follow {
		return watchLive(cmd, ctx, socketPath)
	}

	// One-shot: display current bans and exit
	return displayBans(cmd, ctx, socketPath)
}

// verifyDaemonRunning checks if the daemon socket is accessible.
func verifyDaemonRunning(ctx context.Context, socketPath string) error {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("connect to daemon socket %s: %w", socketPath, err)
	}
	_ = conn.Close() //nolint:errcheck,gosec
	return nil
}

// watchLive continuously polls the daemon and displays bans with updates highlighted.
func watchLive(cmd *cobra.Command, ctx context.Context, socketPath string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var previousBans map[string]bool // Track which IPs we've already seen

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			resp, err := daemonRPC(ctx, socketPath, daemon.SocketRequest{Verb: "list"})
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "error fetching bans: %v\n", err) //nolint:errcheck
				continue
			}

			var bans []daemon.BanEntry
			if err := json.Unmarshal(resp.Data, &bans); err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "error parsing response: %v\n", err) //nolint:errcheck
				continue
			}

			// Find new bans since last update
			currentBans := make(map[string]bool)
			for _, b := range bans {
				currentBans[b.IP] = true
			}

			newBans := make([]daemon.BanEntry, 0)
			for _, b := range bans {
				if !previousBans[b.IP] {
					newBans = append(newBans, b)
				}
			}

			// Display bans
			if jsonOutput {
				_ = writeJSON(cmd.OutOrStdout(), bans)
			} else {
				printBansText(cmd, bans, newBans)
			}

			previousBans = currentBans
		}
	}
}

// displayBans fetches and displays the current ban list once.
func displayBans(cmd *cobra.Command, ctx context.Context, socketPath string) error {
	resp, err := daemonRPC(ctx, socketPath, daemon.SocketRequest{Verb: "list"})
	if err != nil {
		return err
	}

	var bans []daemon.BanEntry
	if err := json.Unmarshal(resp.Data, &bans); err != nil {
		return fmt.Errorf("parse ban list: %w", err)
	}

	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), bans)
	}
	printBansText(cmd, bans, nil)
	return nil
}

// printBansText displays bans in human-readable format.
// newBans highlights recently added bans.
func printBansText(cmd *cobra.Command, bans []daemon.BanEntry, newBans []daemon.BanEntry) {
	w := cmd.OutOrStdout()

	if len(bans) == 0 {
		_, _ = fmt.Fprintf(w, "No active bans\n") //nolint:errcheck
		return
	}

	// Index new bans for highlighting
	isNew := make(map[string]bool)
	for _, b := range newBans {
		isNew[b.IP] = true
	}

	// Sort bans by IP for consistent output
	sort.Slice(bans, func(i, j int) bool {
		return bans[i].IP < bans[j].IP
	})

	_, _ = fmt.Fprintf(w, "Active bans (%d):\n", len(bans))           //nolint:errcheck
	_, _ = fmt.Fprintf(w, "  %-40s  %-12s  %s\n", "IP/CIDR", "TTL", "Reason") //nolint:errcheck
	_, _ = fmt.Fprintf(w, "  %s  %s  %s\n",                         //nolint:errcheck
		repeatStr("─", 40), repeatStr("─", 12), repeatStr("─", 30))

	for _, b := range bans {
		marker := "  "
		if isNew[b.IP] {
			marker = "→ " // Highlight new bans
		}

		reason := b.Reason
		if reason == "" {
			reason = "(no reason)"
		}

		_, _ = fmt.Fprintf(w, "%s%-40s  %-12s  %s\n", //nolint:errcheck
			marker, b.IP, b.TTL, reason)
	}
}
