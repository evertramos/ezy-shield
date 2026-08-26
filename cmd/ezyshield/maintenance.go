package main

// `ezyshield maintenance prune` (issue #184): trigger the retention prune
// through the running daemon's socket. Dry-run is the default-safe path —
// a real run deletes rows and requires the explicit --yes confirmation.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func newMaintenanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "maintenance",
		Short: "Database maintenance operations",
		Long: `Operations on the daemon's SQLite database.

Currently: "prune" applies the retention policy from config.yaml's
retention: section (see the retention reference doc).`,
	}
	cmd.AddCommand(newMaintenancePruneCmd())
	return cmd
}

func newMaintenancePruneCmd() *cobra.Command {
	var (
		socketPath string
		dryRun     bool
		yes        bool
	)

	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Apply the configured retention policy now",
		Long: `Delete rows older than the retention windows configured in config.yaml.

With --dry-run, prints how many rows per table WOULD be deleted and changes
nothing. A real run requires --yes: it deletes in batches, writes a
"retention_prune" summary per table to the audit log, and reclaims file
space when fragmentation warrants it.

Active bans and the allowlist are never touched. The audit log is only
pruned when retention.audit_export_not_required is explicitly true.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !dryRun && !yes {
				return fmt.Errorf("this deletes database rows; re-run with --yes to confirm, or use --dry-run to preview")
			}
			return runMaintenancePrune(cmd, socketPath, dryRun)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"print per-table candidate counts without deleting anything")
	cmd.Flags().BoolVar(&yes, "yes", false,
		"confirm the real (deleting) run")

	return cmd
}

func runMaintenancePrune(cmd *cobra.Command, socketPath string, dryRun bool) error {
	resp, err := daemonRPC(context.Background(), socketPath,
		daemon.SocketRequest{Verb: "prune", DryRun: dryRun})
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), resp)
	}
	var data daemon.PruneData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return fmt.Errorf("decode prune response: %w", err)
	}
	out := cmd.OutOrStdout()
	verbWord := "deleted"
	if data.DryRun {
		verbWord = "would delete"
	}
	if len(data.Tables) == 0 {
		_, _ = fmt.Fprintln(out, "nothing to prune")
	}
	for _, t := range data.Tables {
		_, _ = fmt.Fprintf(out, "%-10s %s %d rows (window %s)\n", t.Table, verbWord, t.Count, humanWindow(t.Window))
	}
	if data.AuditSkipped {
		_, _ = fmt.Fprintln(out, "audit_log: skipped — no export archives the journal; set retention.audit_export_not_required: true to allow pruning it")
	}
	if data.VacuumRan {
		_, _ = fmt.Fprintln(out, "space reclaimed (VACUUM)")
	}
	return nil
}

// humanWindow reformats a Go duration string as whole days when it divides
// evenly ("17520h0m0s" → "730d"); otherwise returns it unchanged.
func humanWindow(s string) string {
	d, err := time.ParseDuration(s)
	if err != nil {
		return s
	}
	if d > 0 && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return s
}
