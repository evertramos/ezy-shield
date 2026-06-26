package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

const (
	nftTable = "inet ezyshield"
	nftSet4  = "blocked"
	nftSet6  = "blocked6"
)

// nftRunner abstracts nft execution so tests can inject a mock.
type nftRunner func(ctx context.Context, script []byte) error

// realNftRunner writes script to a temp file and executes `nft -f <file>`.
// Using -f ensures atomic application: nft parses the whole file before
// committing any changes, satisfying the crash-safety requirement.
func realNftRunner(ctx context.Context, script []byte) error {
	f, err := os.CreateTemp("", "ezyshield-enforcer-*.nft")
	if err != nil {
		return fmt.Errorf("nft: create temp: %w", err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck

	if _, err := f.Write(script); err != nil {
		_ = f.Close()
		return fmt.Errorf("nft: write script: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("nft: close script: %w", err)
	}

	cmd := exec.CommandContext(ctx, "nft", "-f", f.Name()) //nolint:gosec // f.Name() is our own temp file
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -f: %w\n%s", err, bytes.TrimSpace(out))
	}
	return nil
}

// initTable creates the ezyshield table, sets, input chain, and forward chain
// idempotently. Rules are rebuilt on every start to avoid duplicates:
// flush chain (no-op on empty chain) then re-add.
// The forward chain is required to block traffic destined for Docker/container
// ports, which reach the host via DNAT and traverse the FORWARD hook, not INPUT.
func initTable(ctx context.Context, run nftRunner) error {
	script := `add table inet ezyshield
add set inet ezyshield blocked { type ipv4_addr ; flags interval,timeout ; auto-merge ; }
add set inet ezyshield blocked6 { type ipv6_addr ; flags interval,timeout ; auto-merge ; }
add chain inet ezyshield input { type filter hook input priority filter ; policy accept ; }
flush chain inet ezyshield input
add rule inet ezyshield input ip saddr @blocked drop
add rule inet ezyshield input ip6 saddr @blocked6 drop
add chain inet ezyshield forward { type filter hook forward priority filter ; policy accept ; }
flush chain inet ezyshield forward
add rule inet ezyshield forward ip saddr @blocked drop
add rule inet ezyshield forward ip6 saddr @blocked6 drop
`
	return run(ctx, []byte(script))
}

// nftAdd adds ip to the appropriate set with an optional timeout.
// ip must be a pre-validated netip.Addr or netip.Prefix string.
// ttlSec == 0 → permanent (no timeout directive).
func nftAdd(ctx context.Context, run nftRunner, ip string, ttlSec int64) error {
	set, err := setForIP(ip)
	if err != nil {
		return err
	}
	var entry string
	if ttlSec > 0 {
		entry = fmt.Sprintf("%s timeout %ds", ip, ttlSec)
	} else {
		entry = ip
	}
	script := fmt.Sprintf("add element %s %s { %s }\n", nftTable, set, entry)
	return run(ctx, []byte(script))
}

// nftDel removes ip from the appropriate set.
// If nftables reports the element is already gone ("not found in set" or
// "No such file or directory"), the delete is treated as success: the element
// is absent either way. This covers the race where nft auto-expires a timed
// element before the daemon calls Sync/Unban (issue #38).
func nftDel(ctx context.Context, run nftRunner, ip string) error {
	set, err := setForIP(ip)
	if err != nil {
		return err
	}
	script := fmt.Sprintf("delete element %s %s { %s }\n", nftTable, set, ip)
	if err := run(ctx, []byte(script)); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not found in set") || strings.Contains(msg, "No such file or directory") {
			slog.Debug("nftDel: element already absent, ignoring", "ip", ip, "err", err)
			return nil
		}
		return err
	}
	return nil
}

// nftFlush clears both blocked sets.
func nftFlush(ctx context.Context, run nftRunner) error {
	script := fmt.Sprintf("flush set %s %s\nflush set %s %s\n",
		nftTable, nftSet4, nftTable, nftSet6)
	return run(ctx, []byte(script))
}

// nftList returns the current elements of both blocked sets by running
// `nft list set` and parsing the output.
// Falls back to empty slice (not an error) when the set is empty.
func nftList(ctx context.Context) ([]string, error) {
	ips4, err := listSet(ctx, nftSet4)
	if err != nil {
		return nil, err
	}
	ips6, err := listSet(ctx, nftSet6)
	if err != nil {
		return nil, err
	}
	return append(ips4, ips6...), nil
}

func listSet(ctx context.Context, set string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "nft", "list", "set", nftTable, set) //nolint:gosec // table/set names are constants
	out, err := cmd.Output()
	if err != nil {
		// "No such file or directory" means the set doesn't exist yet; treat as empty.
		if strings.Contains(string(out), "No such file") ||
			strings.Contains(err.Error(), "exit status") {
			return nil, nil
		}
		return nil, fmt.Errorf("nft list set %s: %w", set, err)
	}
	return parseSetElements(out), nil
}

// parseSetElements extracts IP/CIDR strings from `nft list set` output.
// It finds the `elements = { ... }` block and parses each comma-separated
// token as a netip.Addr or netip.Prefix, ignoring timeout/expires annotations.
func parseSetElements(out []byte) []string {
	s := string(out)
	start := strings.Index(s, "elements = {")
	if start < 0 {
		return nil
	}
	start += len("elements = {")
	end := strings.Index(s[start:], "}")
	if end < 0 {
		return nil
	}
	block := s[start : start+end]

	var ips []string
	for _, part := range strings.Split(block, ",") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) == 0 {
			continue
		}
		tok := fields[0]
		if _, err := netip.ParseAddr(tok); err == nil {
			ips = append(ips, tok)
			continue
		}
		if pfx, err := netip.ParsePrefix(tok); err == nil {
			ips = append(ips, pfx.String())
		}
	}
	return ips
}

// setForIP returns "blocked" for IPv4 addresses/prefixes, "blocked6" for IPv6.
// Validates that ip is a well-formed address or prefix — no raw nft syntax.
func setForIP(ip string) (string, error) {
	if addr, err := netip.ParseAddr(ip); err == nil {
		if addr.Is4() || addr.Is4In6() {
			return nftSet4, nil
		}
		return nftSet6, nil
	}
	if pfx, err := netip.ParsePrefix(ip); err == nil {
		if pfx.Addr().Is4() || pfx.Addr().Is4In6() {
			return nftSet4, nil
		}
		return nftSet6, nil
	}
	return "", fmt.Errorf("nft: %q is not a valid IP address or CIDR prefix", ip)
}
