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
	"github.com/evertramos/ezy-shield/internal/enforce"
)

const enforcerDialTimeout = 500 * time.Millisecond

func newStatusCmd() *cobra.Command {
	var socketPath, enforcerSocketPath string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show daemon and enforcer status",
		Long:  `Query the EzyShield daemon and print its current status.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(cmd, socketPath, enforcerSocketPath)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().StringVar(&enforcerSocketPath, "enforcer-socket", enforce.DefaultSocketPath,
		"path to enforcer control socket")

	return cmd
}

// StatusOutput is the stable schema for --json output.
type StatusOutput struct {
	Daemon       string         `json:"daemon"`
	Enforcer     string         `json:"enforcer"`
	Mode         string         `json:"mode,omitempty"`
	Uptime       string         `json:"uptime,omitempty"`
	Version      string         `json:"version,omitempty"`
	ActiveBans   int            `json:"active_bans"`
	BansByStrike map[string]int `json:"bans_by_strike,omitempty"`
	Message      string         `json:"message,omitempty"`
}

func runStatus(cmd *cobra.Command, socketPath, enforcerSocketPath string) error {
	ctx := context.Background()
	out := StatusOutput{}
	out.Enforcer = probeSocket(ctx, enforcerSocketPath)

	resp, err := daemonRPC(ctx, socketPath, daemon.SocketRequest{Verb: "status"})
	if err != nil {
		out.Daemon = "stopped"
		out.Message = err.Error()
		return printStatusOutput(cmd, out)
	}
	out.Daemon = "running"

	var sd daemon.StatusData
	if err := json.Unmarshal(resp.Data, &sd); err != nil {
		return fmt.Errorf("parse status response: %w", err)
	}
	out.Uptime = sd.Uptime
	out.Version = sd.Version
	out.ActiveBans = sd.ActiveBans
	if sd.Armed {
		out.Mode = "enforce"
	} else {
		out.Mode = "dry-run"
	}

	bansByStrike, err := fetchBansByStrike(ctx, socketPath)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not fetch per-strike counts: %v\n", err)
	} else {
		out.BansByStrike = bansByStrike
	}

	return printStatusOutput(cmd, out)
}

// probeSocket returns "running" if the socket accepts a connection, else "stopped".
func probeSocket(ctx context.Context, socketPath string) string {
	dialCtx, cancel := context.WithTimeout(ctx, enforcerDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", socketPath)
	if err != nil {
		return "stopped"
	}
	_ = conn.Close()
	return "running"
}

// fetchBansByStrike issues the list verb and aggregates ban counts by strike tier.
func fetchBansByStrike(ctx context.Context, socketPath string) (map[string]int, error) {
	resp, err := daemonRPC(ctx, socketPath, daemon.SocketRequest{Verb: "list"})
	if err != nil {
		return nil, fmt.Errorf("list verb: %w", err)
	}
	var entries []daemon.BanEntry
	if err := json.Unmarshal(resp.Data, &entries); err != nil {
		return nil, fmt.Errorf("parse list response: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil
	}
	counts := make(map[string]int)
	for _, e := range entries {
		counts[strikeKey(e.Strike, e.TTL)]++
	}
	return counts, nil
}

func strikeKey(strike int, ttl string) string {
	if strike == 0 || ttl == "permanent" {
		return "permanent"
	}
	return fmt.Sprintf("strike %d", strike)
}

func printStatusOutput(cmd *cobra.Command, out StatusOutput) error {
	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), out)
	}
	return printStatusText(cmd, out)
}

func printStatusText(cmd *cobra.Command, out StatusOutput) error {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "daemon:    %s\n", out.Daemon)
	fmt.Fprintf(w, "enforcer:  %s\n", out.Enforcer)
	if out.Daemon == "stopped" {
		if out.Message != "" {
			fmt.Fprintf(w, "message:   %s\n", out.Message)
		}
		return nil
	}
	fmt.Fprintf(w, "mode:      %s\n", out.Mode)
	fmt.Fprintf(w, "uptime:    %s\n", out.Uptime)
	fmt.Fprintf(w, "version:   %s\n", out.Version)
	fmt.Fprintf(w, "bans:      %d\n", out.ActiveBans)
	if len(out.BansByStrike) > 0 {
		keys := make([]string, 0, len(out.BansByStrike))
		for k := range out.BansByStrike {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i] == "permanent" {
				return false
			}
			if keys[j] == "permanent" {
				return true
			}
			return keys[i] < keys[j]
		})
		fmt.Fprintln(w, "  by strike:")
		for _, k := range keys {
			fmt.Fprintf(w, "    %-12s %d\n", k+":", out.BansByStrike[k])
		}
	}
	return nil
}
