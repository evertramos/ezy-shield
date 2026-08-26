package main

// `ezyshield feeds` — status and on-demand refresh of the reputation feeds
// (issue #196), over the existing unix-socket control API.

import (
	"context"
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func newFeedsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feeds",
		Short: "Inspect and refresh the configured IP reputation feeds",
		Long: `Reputation feeds (config.yaml 'feeds' section) are downloaded on their
own schedule by the daemon. This command talks to the running daemon:

  feeds status          per-feed state: last/next refresh, entries, skipped
  feeds refresh [name]  re-fetch one feed (or all) right now`,
	}
	cmd.AddCommand(newFeedsStatusCmd(), newFeedsRefreshCmd())
	return cmd
}

func newFeedsStatusCmd() *cobra.Command {
	var (
		socketPath string
		jsonOutput bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show per-feed refresh state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resp, err := daemonRPC(context.Background(), socketPath,
				daemon.SocketRequest{Verb: "feeds_status"})
			if err != nil {
				return err
			}
			var entries []daemon.FeedStatusEntry
			if err := json.Unmarshal(resp.Data, &entries); err != nil {
				return fmt.Errorf("decode feeds status: %w", err)
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), entries)
			}
			if len(entries) == 0 {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "feeds configured, but none has refreshed yet — try 'feeds refresh'")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "FEED\tACTION\tENTRIES\tSKIPPED\tLAST REFRESH\tNEXT REFRESH")
			for _, e := range entries {
				next := "-"
				if !e.NextRefresh.IsZero() {
					next = fmt.Sprintf("in %s", time.Until(e.NextRefresh).Round(time.Minute))
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s ago\t%s\n",
					sanitizeField(e.Name, 32), e.Action, e.Entries, e.Skipped,
					time.Since(e.LastRefresh).Round(time.Second), next)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "machine-readable output")
	return cmd
}

func newFeedsRefreshCmd() *cobra.Command {
	var socketPath string
	cmd := &cobra.Command{
		Use:   "refresh [name]",
		Short: "Re-fetch one feed (or all feeds) immediately",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			resp, err := daemonRPC(context.Background(), socketPath,
				daemon.SocketRequest{Verb: "feeds_refresh", Name: name})
			if err != nil {
				return err
			}
			var data daemon.FeedsRefreshData
			if err := json.Unmarshal(resp.Data, &data); err != nil {
				return fmt.Errorf("decode refresh result: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "refreshed %d feed(s) — see 'feeds status'\n", data.Refreshed)
			return nil
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	return cmd
}
