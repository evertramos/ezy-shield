package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/evertramos/ezy-shield/internal/nftnames"
)

// errElementAbsent is a stable, typed sentinel that nftDel and nftDelAllow
// return when nft reports the target element is already gone from the set —
// e.g. because nft's native per-element `timeout` fired between the caller's
// list and delete (issue #39). Callers dispatch on this via errors.Is and
// translate it into the wire-level enforce.CodeAlreadyAbsent response — the
// nft stderr string is never propagated to the client, which lets the client
// stay agnostic to nft version-to-version wording changes.
var errElementAbsent = errors.New("nft: element already absent")

// nftAbsentSignals lists all nft error substrings that mean "the element you
// asked me to delete is not in the set". Detected at the helper (one hop
// before the wire) so the client never has to parse nft stderr — see the
// package comment for enforce.CodeAlreadyAbsent. Add new variants here as
// they surface in the wild.
//
// Known variants:
//   - "not found in set" — older nft, delete of a single element that isn't
//     present in an `interval`-flagged set.
//   - "element does not exist" — nftables 1.0+ / current stable Debian/Ubuntu;
//     what the live kylian-s host was emitting when issue #39 was filed.
//   - "No such file or directory" — surfaces when the set itself is missing
//     (racy startup ordering). Treated as absent for delete symmetry.
var nftAbsentSignals = []string{
	"not found in set",
	"element does not exist",
	"No such file or directory",
}

// isNftAbsentErr reports whether msg contains any known nft "already absent"
// signal. Substring match is intentional: nft prefixes with "Error: " and
// often includes file:line context and the offending script line.
func isNftAbsentErr(msg string) bool {
	for _, s := range nftAbsentSignals {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// Table and set names are no longer compile-time constants (issue #268):
// every function below receives an nftnames.Names that was resolved and
// validated IN THIS PROCESS via nftnames.Resolve — the conservative
// identifier charset there is what makes interpolating the names into nft
// scripts safe. Nothing else may reach script generation.

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
//
// Layout (issue #23):
//   - prerouting chain at priority `raw` (-300) — the earliest hook, runs
//     before conntrack, before NAT, before docker-proxy accepts, and before
//     Podman rootless slirp4netns/pasta. This is the canonical placement per
//     the nftables wiki for pure-drop blocklists and matches the design of
//     CrowdSec's cs-firewall-bouncer.
//   - Allowlist rules (@allowed / @allowed6) come first — anti-lockout
//     invariant (AGENTS.md §2): allowlist ALWAYS wins on the same hook.
//   - `notrack` before `drop` skips conntrack for packets we're about to
//     drop, saving state entries under scanner floods (recommended pattern
//     in the netfilter wiki).
//   - input + forward chains at priority `filter` (0) are kept unchanged as
//     defense in depth. If for any reason a packet bypasses the raw drop
//     (module reload race, external `nft flush ruleset`), these catch it.
//
// The allowed sets do not use `timeout` — allowlist TTLs are enforced by the
// daemon which syncs the set on entry expiration. Blocked sets do use nft's
// native `timeout` for ban expiry.
func initTable(ctx context.Context, run nftRunner, n nftnames.Names) error {
	// The %[1]s..%[5]s values come exclusively from nftnames.Resolve — the
	// strict identifier charset there is the injection barrier.
	script := fmt.Sprintf(`add table %[1]s
add set %[1]s %[2]s { type ipv4_addr ; flags interval,timeout ; auto-merge ; }
add set %[1]s %[3]s { type ipv6_addr ; flags interval,timeout ; auto-merge ; }
add set %[1]s %[4]s { type ipv4_addr ; flags interval ; auto-merge ; }
add set %[1]s %[5]s { type ipv6_addr ; flags interval ; auto-merge ; }
add chain %[1]s prerouting { type filter hook prerouting priority raw ; policy accept ; }
flush chain %[1]s prerouting
add rule %[1]s prerouting ip saddr @%[4]s accept
add rule %[1]s prerouting ip6 saddr @%[5]s accept
add rule %[1]s prerouting ip saddr @%[2]s notrack
add rule %[1]s prerouting ip6 saddr @%[3]s notrack
add rule %[1]s prerouting ip saddr @%[2]s drop
add rule %[1]s prerouting ip6 saddr @%[3]s drop
add chain %[1]s input { type filter hook input priority filter ; policy accept ; }
flush chain %[1]s input
add rule %[1]s input ip saddr @%[2]s drop
add rule %[1]s input ip6 saddr @%[3]s drop
add chain %[1]s forward { type filter hook forward priority filter ; policy accept ; }
flush chain %[1]s forward
add rule %[1]s forward ip saddr @%[2]s drop
add rule %[1]s forward ip6 saddr @%[3]s drop
`, n.Table, n.Set4, n.Set6, n.Allow4, n.Allow6)
	return run(ctx, []byte(script))
}

// nftAdd adds ip to the appropriate set with an optional timeout.
// ip must be a pre-validated netip.Addr or netip.Prefix string.
// ttlSec == 0 → permanent (no timeout directive).
func nftAdd(ctx context.Context, run nftRunner, n nftnames.Names, ip string, ttlSec int64) error {
	set, err := setForIP(n, ip)
	if err != nil {
		return err
	}
	var entry string
	if ttlSec > 0 {
		entry = fmt.Sprintf("%s timeout %ds", ip, ttlSec)
	} else {
		entry = ip
	}
	script := fmt.Sprintf("add element %s %s { %s }\n", n.Table, set, entry)
	return run(ctx, []byte(script))
}

// nftDel removes ip from the appropriate set. If nftables reports the element
// is already gone (see nftAbsentSignals), it returns errElementAbsent so the
// dispatch layer can translate that into a typed enforce.CodeAlreadyAbsent
// response — never propagating raw nft stderr to the client (issue #39).
func nftDel(ctx context.Context, run nftRunner, n nftnames.Names, ip string) error {
	set, err := setForIP(n, ip)
	if err != nil {
		return err
	}
	script := fmt.Sprintf("delete element %s %s { %s }\n", n.Table, set, ip)
	if err := run(ctx, []byte(script)); err != nil {
		if isNftAbsentErr(err.Error()) {
			slog.Debug("nftDel: element already absent", "ip", ip)
			return errElementAbsent
		}
		return err
	}
	return nil
}

// nftFlush clears both blocked sets.
func nftFlush(ctx context.Context, run nftRunner, n nftnames.Names) error {
	script := fmt.Sprintf("flush set %s %s\nflush set %s %s\n",
		n.Table, n.Set4, n.Table, n.Set6)
	return run(ctx, []byte(script))
}

// nftAddAllow adds ip to the appropriate @allowed set. Unlike @blocked,
// allowlist entries have no nft-native timeout — the daemon owns TTL and
// syncs the set on expiry. Idempotent: adding an already-present element
// succeeds (nft add is a no-op on duplicates for interval sets).
func nftAddAllow(ctx context.Context, run nftRunner, n nftnames.Names, ip string) error {
	set, err := allowSetForIP(n, ip)
	if err != nil {
		return err
	}
	script := fmt.Sprintf("add element %s %s { %s }\n", n.Table, set, ip)
	return run(ctx, []byte(script))
}

// nftDelAllow removes ip from the appropriate @allowed set. Missing element
// is signalled via errElementAbsent — same handling as nftDel; the allow set
// has no nft-native timeout today but the code paths stay symmetric so a
// future refactor cannot accidentally split their behaviour (issue #39, §5).
func nftDelAllow(ctx context.Context, run nftRunner, n nftnames.Names, ip string) error {
	set, err := allowSetForIP(n, ip)
	if err != nil {
		return err
	}
	script := fmt.Sprintf("delete element %s %s { %s }\n", n.Table, set, ip)
	if err := run(ctx, []byte(script)); err != nil {
		if isNftAbsentErr(err.Error()) {
			slog.Debug("nftDelAllow: element already absent", "ip", ip)
			return errElementAbsent
		}
		return err
	}
	return nil
}

// nftListAllow returns the current elements of both allowed sets.
func nftListAllow(ctx context.Context, n nftnames.Names) ([]string, error) {
	ips4, err := listSet(ctx, n, n.Allow4)
	if err != nil {
		return nil, err
	}
	ips6, err := listSet(ctx, n, n.Allow6)
	if err != nil {
		return nil, err
	}
	return append(ips4, ips6...), nil
}

// nftFlushAllow clears both allowed sets. Used by the daemon at startup
// before re-adding the full allowlist (idempotent sync).
func nftFlushAllow(ctx context.Context, run nftRunner, n nftnames.Names) error {
	script := fmt.Sprintf("flush set %s %s\nflush set %s %s\n",
		n.Table, n.Allow4, n.Table, n.Allow6)
	return run(ctx, []byte(script))
}

// nftList returns the current elements of both blocked sets by running
// `nft list set` and parsing the output.
// Falls back to empty slice (not an error) when the set is empty.
func nftList(ctx context.Context, n nftnames.Names) ([]string, error) {
	ips4, err := listSet(ctx, n, n.Set4)
	if err != nil {
		return nil, err
	}
	ips6, err := listSet(ctx, n, n.Set6)
	if err != nil {
		return nil, err
	}
	return append(ips4, ips6...), nil
}

func listSet(ctx context.Context, n nftnames.Names, set string) ([]string, error) {
	// n.Table is "family name"; nft's CLI wants them as separate argv words.
	family, tbl, _ := strings.Cut(n.Table, " ")
	cmd := exec.CommandContext(ctx, "nft", "list", "set", family, tbl, set) //nolint:gosec // names validated by nftnames.Resolve in this process
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

// setForIP returns the v4 or v6 blocked set for ip.
// Validates that ip is a well-formed address or prefix — no raw nft syntax.
func setForIP(n nftnames.Names, ip string) (string, error) {
	return setForIPIn(ip, n.Set4, n.Set6)
}

// allowSetForIP is the @allowed counterpart of setForIP.
func allowSetForIP(n nftnames.Names, ip string) (string, error) {
	return setForIPIn(ip, n.Allow4, n.Allow6)
}

// setForIPIn picks the v4 or v6 set name for ip. Shared by setForIP and
// allowSetForIP so validation stays in one place — no raw nft syntax reaches
// script generation.
func setForIPIn(ip, set4, set6 string) (string, error) {
	if addr, err := netip.ParseAddr(ip); err == nil {
		if addr.Is4() || addr.Is4In6() {
			return set4, nil
		}
		return set6, nil
	}
	if pfx, err := netip.ParsePrefix(ip); err == nil {
		if pfx.Addr().Is4() || pfx.Addr().Is4In6() {
			return set4, nil
		}
		return set6, nil
	}
	return "", fmt.Errorf("nft: %q is not a valid IP address or CIDR prefix", ip)
}
