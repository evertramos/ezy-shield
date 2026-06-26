package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/scan"
	"github.com/evertramos/ezy-shield/internal/store"
)

func newScanCmd() *cobra.Command {
	var dbPath string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Discover listening sockets and detect drift vs baseline",
		Long: `Scan /proc/net/tcp[6] to list every listening socket with PID, binary path,
user, owner (systemd unit or Docker container), and log source.

Results are stored as a baseline in SQLite. On subsequent runs, new listeners
that did not exist in the previous baseline are flagged. Public listeners with
no resolvable log source are reported as "⚠ no logs".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd, dbPath)
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/ezyshield/ezyshield.db",
		"path to SQLite database")

	return cmd
}

// scanOutput is the JSON envelope returned by --json.
type scanOutput struct {
	Listeners    []scan.Listener `json:"listeners"`
	NewListeners []scan.Listener `json:"new_listeners"`
}

func runScan(cmd *cobra.Command, dbPath string) error {
	ctx := cmd.Context()

	if err := os.MkdirAll(dirOf(dbPath), 0o750); err != nil {
		return fmt.Errorf("scan: create db dir: %w", err)
	}

	db, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("scan: open store: %w", err)
	}
	defer db.Close() //nolint:errcheck

	sc := scan.New(scan.Sources{})
	listeners, err := sc.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	// Load current baseline for drift detection.
	baseline, err := db.ScanBaseline(ctx)
	if err != nil {
		return fmt.Errorf("scan: load baseline: %w", err)
	}
	newOnes := findNewListeners(baseline, listeners)

	// Persist updated scan results.
	for _, l := range listeners {
		if err := db.UpsertScanRecord(ctx, listenerToRecord(l)); err != nil {
			return fmt.Errorf("scan: persist: %w", err)
		}
	}

	// Warn about new listeners.
	for _, l := range newOnes {
		slog.WarnContext(ctx, "scan: NEW listener detected",
			"proto", l.Protocol,
			"addr", l.Addr,
			"pid", l.PID,
			"exe", l.ExePath,
			"owner_type", l.OwnerType,
			"log_source", l.LogSource,
		)
	}

	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), scanOutput{
			Listeners:    listeners,
			NewListeners: newOnes,
		})
	}

	return printScanTable(cmd.OutOrStdout(), listeners, newOnes)
}

// findNewListeners returns listeners in current that are absent from baseline,
// keyed on (proto, addr:port).
func findNewListeners(baseline []store.ScanRecord, current []scan.Listener) []scan.Listener {
	seen := make(map[string]struct{}, len(baseline))
	for _, r := range baseline {
		seen[r.Proto+":"+r.LocalAddr] = struct{}{}
	}
	var out []scan.Listener
	for _, l := range current {
		if _, ok := seen[l.Protocol+":"+l.Addr.String()]; !ok {
			out = append(out, l)
		}
	}
	return out
}

// listenerToRecord converts a scan.Listener into a store.ScanRecord for
// persistence. The two types are kept separate to avoid a store→scan import.
func listenerToRecord(l scan.Listener) store.ScanRecord {
	return store.ScanRecord{
		Proto:          l.Protocol,
		LocalAddr:      l.Addr.String(),
		PID:            l.PID,
		ExePath:        l.ExePath,
		UID:            l.UID,
		UserName:       l.UserName,
		IsPublic:       l.IsPublic,
		OwnerType:      l.OwnerType,
		UnitName:       l.UnitName,
		ContainerID:    l.ContainerID,
		ContainerName:  l.ContainerName,
		ContainerImage: l.ContainerImage,
		LogSource:      l.LogSource,
	}
}

// printScanTable renders listeners as a tab-aligned table, prefixing new
// listeners with "[NEW]". It returns any write or flush error.
func printScanTable(w io.Writer, listeners []scan.Listener, newOnes []scan.Listener) error {
	isNew := make(map[string]struct{}, len(newOnes))
	for _, l := range newOnes {
		isNew[l.Protocol+":"+l.Addr.String()] = struct{}{}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "PROTO\tADDR:PORT\tPID\tBINARY\tUSER\tOWNER\tUNIT/CONTAINER\tLOG SOURCE"); err != nil {
		return err
	}
	for _, l := range listeners {
		flag := ""
		if _, ok := isNew[l.Protocol+":"+l.Addr.String()]; ok {
			flag = "[NEW] "
		}
		owner := l.UnitName
		if l.OwnerType == "docker" {
			owner = l.ContainerName
			if owner == "" && len(l.ContainerID) >= 12 {
				owner = l.ContainerID[:12]
			}
		}
		exe := l.ExePath
		if exe == "" {
			exe = "?"
		}
		if _, err := fmt.Fprintf(tw, "%s%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			flag, l.Protocol,
			l.Addr.String(),
			l.PID, exe,
			l.UserName,
			l.OwnerType,
			owner,
			l.LogSource,
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}
