package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// auditReasonMax caps the untrusted, log-derived reason column in the
// --audit table so a crafted reason cannot flood the terminal.
const auditReasonMax = 200

func newListCmd() *cobra.Command {
	var (
		socketPath string
		byCountry  bool
		byASN      bool
		allow      bool
		audit      bool
		auditIP    string
		auditLimit int
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active bans (or allowlist entries) from the running daemon",
		Long: `Query the daemon and print the current set of active bans.

This is a point-in-time snapshot — to follow events live as they happen
(detections, strikes, bans) use the 'watch' command instead.

Use --allow to list the persisted allowlist instead, including expiry info.

Use --audit to print the historical action log (bans, expiries, unbans,
allows) newest-first, instead of the active-ban snapshot. --ip filters the
history to one address and --limit caps the number of rows (default 100).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if audit {
				if allow || byCountry || byASN {
					return fmt.Errorf("--audit cannot be combined with --allow/--by-country/--by-asn")
				}
				return runListAudit(cmd, socketPath, auditIP, auditLimit)
			}
			if auditIP != "" || cmd.Flags().Changed("limit") {
				return fmt.Errorf("--ip and --limit only apply with --audit")
			}
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
	cmd.Flags().BoolVar(&audit, "audit", false,
		"show the historical action log instead of active bans")
	cmd.Flags().StringVar(&auditIP, "ip", "",
		"with --audit: filter the history to a single IP address")
	cmd.Flags().IntVar(&auditLimit, "limit", 100,
		"with --audit: maximum number of rows to return")

	return cmd
}

// runListAudit queries the daemon's audit history via the "events" verb and
// prints it newest-first. --ip narrows to one exact address; --limit caps rows.
func runListAudit(cmd *cobra.Command, socketPath, ip string, limit int) error {
	resp, err := daemonRPC(context.Background(), socketPath,
		daemon.SocketRequest{Verb: "events", IP: ip, Limit: limit})
	if err != nil {
		return err
	}

	var entries []daemon.EventEntry
	if err := json.Unmarshal(resp.Data, &entries); err != nil {
		return fmt.Errorf("parse events response: %w", err)
	}

	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), entries)
	}

	if len(entries) == 0 {
		msg := "no recorded actions"
		if ip != "" {
			msg = "no recorded actions for " + ip
		}
		_, err := fmt.Fprintln(cmd.OutOrStdout(), msg)
		return err
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tIP\tACTION\tSTRIKE\tTTL\tREASON") //nolint:errcheck
	for _, e := range entries {
		// IP and Op are daemon-written (an address/CIDR and a fixed op set);
		// Reason is the only untrusted, log-derived field, so sanitize it.
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck
			formatAuditTime(e.RecordedAt), e.IP, e.Op,
			auditStrike(e.Strike), auditTTL(e.Op, e.TTLSeconds),
			sanitizeField(e.Reason, auditReasonMax))
	}
	return w.Flush()
}

// formatAuditTime renders a stored RFC 3339 timestamp as "YYYY-MM-DD HH:MM:SS"
// in UTC. The value is daemon-written and always valid; on the off chance it
// isn't parseable it is sanitized and returned as-is rather than dropped.
func formatAuditTime(recordedAt string) string {
	t, err := time.Parse(time.RFC3339, recordedAt)
	if err != nil {
		return sanitizeField(recordedAt, 40)
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

// auditStrike renders the STRIKE column: the strike number, or "-" for actions
// that carry none (expiries, unbans, manual permanent bans).
func auditStrike(n int) string {
	if n <= 0 {
		return "-"
	}
	return strconv.Itoa(n)
}

// auditTTL renders the TTL column: a duration for timed bans, "perm" for a ban
// with TTL 0 (permanent), and "-" for actions that carry no TTL (expiry, unban,
// allow).
func auditTTL(op string, ttlSeconds int64) string {
	if ttlSeconds > 0 {
		return (time.Duration(ttlSeconds) * time.Second).String()
	}
	if op == "ban" {
		return "perm"
	}
	return "-"
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
		ttl := e.TTL
		if e.Simulated {
			// Dry-run simulated ban (ADR-0009 §5): recorded, never enforced.
			ttl += " (simulated)"
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n", //nolint:errcheck
			e.IP, e.Strike, ttl, e.Country, e.ASN, e.Reason)
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
