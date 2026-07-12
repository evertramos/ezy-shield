package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func newListCmd() *cobra.Command {
	var (
		socketPath string
		byCountry  bool
		byASN      bool
		allow      bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active bans (or allowlist entries) from the running daemon",
		Long: `Query the daemon and print the current set of active bans.

This is a point-in-time snapshot — to follow events live as they happen
(detections, strikes, bans) use the 'watch' command instead.

Use --allow to list the persisted allowlist instead, including expiry info.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if allow {
				return runListAllow(cmd, socketPath)
			}
			return runList(cmd, socketPath, byCountry, byASN)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to daemon control socket")
	cmd.Flags().BoolVar(&byCountry, "by-country", false,
		"group bans by country (requires GeoIP enrichment)")
	cmd.Flags().BoolVar(&byASN, "by-asn", false,
		"group bans by ASN (requires GeoIP enrichment)")
	cmd.Flags().BoolVar(&allow, "allow", false,
		"list allowlist entries instead of bans")

	return cmd
}

func runList(cmd *cobra.Command, socketPath string, byCountry, byASN bool) error {
	resp, err := daemonRPC(context.Background(), socketPath,
		daemon.SocketRequest{Verb: "list"})
	if err != nil {
		return err
	}

	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), resp)
	}

	var entries []daemon.BanEntry
	if err := json.Unmarshal(resp.Data, &entries); err != nil {
		return fmt.Errorf("parse list response: %w", err)
	}

	if len(entries) == 0 {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "no active bans")
		return err
	}

	switch {
	case byCountry:
		return printByCountry(cmd, entries)
	case byASN:
		return printByASN(cmd, entries)
	default:
		return printBanTable(cmd, entries)
	}
}

func runListAllow(cmd *cobra.Command, socketPath string) error {
	resp, err := daemonRPC(context.Background(), socketPath,
		daemon.SocketRequest{Verb: "list_allow"})
	if err != nil {
		return err
	}

	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), resp)
	}

	var entries []daemon.AllowEntry
	if err := json.Unmarshal(resp.Data, &entries); err != nil {
		return fmt.Errorf("parse list_allow response: %w", err)
	}

	if len(entries) == 0 {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "no allowlist entries")
		return err
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP/CIDR\tEXPIRES\tREASON") //nolint:errcheck
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\n", e.Prefix, e.Expires, e.Reason) //nolint:errcheck
	}
	return w.Flush()
}

func printBanTable(cmd *cobra.Command, entries []daemon.BanEntry) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tSTRIKE\tTTL\tCOUNTRY\tASN\tREASON") //nolint:errcheck
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n", //nolint:errcheck
			e.IP, e.Strike, e.TTL, e.Country, e.ASN, e.Reason)
	}
	return w.Flush()
}

func printByCountry(cmd *cobra.Command, entries []daemon.BanEntry) error {
	groups := make(map[string][]daemon.BanEntry)
	for _, e := range entries {
		key := e.Country
		if key == "" {
			key = "(unknown)"
		}
		groups[key] = append(groups[key], e)
	}

	keys := sortedKeys(groups)
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	for _, country := range keys {
		fmt.Fprintf(w, "Country: %s (%d ban(s))\n", country, len(groups[country])) //nolint:errcheck
		fmt.Fprintln(w, "  IP\tSTRIKE\tTTL\tREASON")                               //nolint:errcheck
		for _, e := range groups[country] {
			fmt.Fprintf(w, "  %s\t%d\t%s\t%s\n", e.IP, e.Strike, e.TTL, e.Reason) //nolint:errcheck
		}
		fmt.Fprintln(w) //nolint:errcheck
	}
	return w.Flush()
}

func printByASN(cmd *cobra.Command, entries []daemon.BanEntry) error {
	groups := make(map[string][]daemon.BanEntry)
	for _, e := range entries {
		key := e.ASN
		if key == "" {
			key = "(unknown)"
		}
		groups[key] = append(groups[key], e)
	}

	keys := sortedKeys(groups)
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	for _, asn := range keys {
		fmt.Fprintf(w, "ASN: %s (%d ban(s))\n", asn, len(groups[asn])) //nolint:errcheck
		fmt.Fprintln(w, "  IP\tSTRIKE\tTTL\tREASON")                   //nolint:errcheck
		for _, e := range groups[asn] {
			fmt.Fprintf(w, "  %s\t%d\t%s\t%s\n", e.IP, e.Strike, e.TTL, e.Reason) //nolint:errcheck
		}
		fmt.Fprintln(w) //nolint:errcheck
	}
	return w.Flush()
}

func sortedKeys(m map[string][]daemon.BanEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
