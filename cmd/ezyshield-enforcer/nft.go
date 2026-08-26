package main

// Atomicity contract (issue #214). One `nft` invocation applies its whole
// script as a single kernel transaction, so a crash/OOM-kill of this helper
// can never leave a PARTIAL nft script applied. Per logical operation:
//
//   - initTable, add element, delete element, flush, and every allow_* verb:
//     one nft invocation each → atomic. Interrupting the helper between the
//     kernel write and the cache write only stales the in-memory cache, which
//     init() rebuilds from the kernel (with per-element `expires`, issue
//     #383) on the next start.
//   - replace-on-re-add (dispatch "add" when the cache holds the element):
//     TWO invocations (delete, then add) — NOT atomic. Recovery: on a failed
//     add the previous element is restored with its remaining lifetime; if
//     the rollback also fails, the cache is made to agree with the empty
//     kernel so the daemon's periodic reconcile re-adds from the store.
//   - name switch (switchNamesLocked): multi-step but idempotent — initTable
//     is create-if-absent and nothing is deleted until the new table is live;
//     a failure mid-switch leaves the old table untouched and a retry
//     converges. No destructive rollback is attempted: the target table may
//     have pre-existed with operator state we must not delete.
//
// The store↔kernel backstop for every non-atomic window is the daemon's
// reconcile (startup + periodic Sync), which repairs both directions and now
// reports repair counts for auditing (issue #214).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforce"
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
add set %[1]s %[6]s { type ipv4_addr ; flags interval,timeout ; auto-merge ; }
add set %[1]s %[7]s { type ipv6_addr ; flags interval,timeout ; auto-merge ; }
add chain %[1]s prerouting { type filter hook prerouting priority raw ; policy accept ; }
flush chain %[1]s prerouting
add rule %[1]s prerouting ip saddr @%[4]s accept
add rule %[1]s prerouting ip6 saddr @%[5]s accept
add rule %[1]s prerouting ip saddr @%[2]s notrack
add rule %[1]s prerouting ip6 saddr @%[3]s notrack
add rule %[1]s prerouting ip saddr @%[2]s drop
add rule %[1]s prerouting ip6 saddr @%[3]s drop
add rule %[1]s prerouting ip saddr @%[6]s notrack
add rule %[1]s prerouting ip6 saddr @%[7]s notrack
add rule %[1]s prerouting ip saddr @%[6]s drop
add rule %[1]s prerouting ip6 saddr @%[7]s drop
add chain %[1]s input { type filter hook input priority filter ; policy accept ; }
flush chain %[1]s input
add rule %[1]s input ip saddr @%[2]s drop
add rule %[1]s input ip6 saddr @%[3]s drop
add rule %[1]s input ip saddr @%[6]s drop
add rule %[1]s input ip6 saddr @%[7]s drop
add chain %[1]s forward { type filter hook forward priority filter ; policy accept ; }
flush chain %[1]s forward
add rule %[1]s forward ip saddr @%[2]s drop
add rule %[1]s forward ip6 saddr @%[3]s drop
add rule %[1]s forward ip saddr @%[6]s drop
add rule %[1]s forward ip6 saddr @%[7]s drop
`, n.Table, n.Set4, n.Set6, n.Allow4, n.Allow6, n.Feeds4, n.Feeds6)
	return run(ctx, []byte(script))
}

// nftFeedsSync atomically replaces the reputation-feed sets with exactly the
// given elements (issue #195): one `nft -f` script flushes both feed sets
// and re-adds every element with its timeout, so the kernel never observes a
// partial state. Elements were validated by the dispatch layer; each IP is
// a netip-parsed Addr/Prefix string and every TTL is > 0 (feed entries are
// never permanent).
func nftFeedsSync(ctx context.Context, run nftRunner, n nftnames.Names, elems []enforce.FeedElement) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "flush set %s %s\nflush set %s %s\n", n.Table, n.Feeds4, n.Table, n.Feeds6)
	var v4, v6 []string
	for _, e := range elems {
		set, err := setForIPIn(e.IP, "4", "6")
		if err != nil {
			return err
		}
		entry := fmt.Sprintf("%s timeout %ds", e.IP, e.TTLSeconds)
		if set == "4" {
			v4 = append(v4, entry)
		} else {
			v6 = append(v6, entry)
		}
	}
	// Batch adds in chunks so no single script line grows unbounded.
	const chunk = 512
	writeChunks := func(set string, entries []string) {
		for len(entries) > 0 {
			n2 := min(chunk, len(entries))
			fmt.Fprintf(&b, "add element %s %s { %s }\n", n.Table, set, strings.Join(entries[:n2], ", "))
			entries = entries[n2:]
		}
	}
	writeChunks(n.Feeds4, v4)
	writeChunks(n.Feeds6, v6)
	return run(ctx, b.Bytes())
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

// nftListAllow returns the current elements of both allowed sets. Allow
// entries carry no nft-native timeout, so only the IP strings are returned.
func nftListAllow(ctx context.Context, n nftnames.Names) ([]string, error) {
	els4, err := listSet(ctx, n, n.Allow4)
	if err != nil {
		return nil, err
	}
	els6, err := listSet(ctx, n, n.Allow6)
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(els4)+len(els6))
	for _, e := range append(els4, els6...) {
		ips = append(ips, e.ip)
	}
	return ips, nil
}

// nftFlushAllow clears both allowed sets. Used by the daemon at startup
// before re-adding the full allowlist (idempotent sync).
func nftFlushAllow(ctx context.Context, run nftRunner, n nftnames.Names) error {
	script := fmt.Sprintf("flush set %s %s\nflush set %s %s\n",
		n.Table, n.Allow4, n.Table, n.Allow6)
	return run(ctx, []byte(script))
}

// nftList returns the current elements of both blocked sets (with remaining
// lifetimes) by running `nft list set` and parsing the output.
// Falls back to empty slice (not an error) when the set is empty.
func nftList(ctx context.Context, n nftnames.Names) ([]setElem, error) {
	els4, err := listSet(ctx, n, n.Set4)
	if err != nil {
		return nil, err
	}
	els6, err := listSet(ctx, n, n.Set6)
	if err != nil {
		return nil, err
	}
	return append(els4, els6...), nil
}

// listSetOutput runs `nft list set` and returns its stdout. It is a variable
// so tests can inject failures; this is the one nft invocation that needs
// captured stdout, so it cannot go through nftRunner (fire-and-forget
// script execution).
var listSetOutput = func(ctx context.Context, family, tbl, set string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "nft", "list", "set", family, tbl, set) //nolint:gosec // names validated by nftnames.Resolve in this process
	return cmd.Output()
}

func listSet(ctx context.Context, n nftnames.Names, set string) ([]setElem, error) {
	// n.Table is "family name"; nft's CLI wants them as separate argv words.
	family, tbl, _ := strings.Cut(n.Table, " ")
	out, err := listSetOutput(ctx, family, tbl, set)
	if err != nil {
		// The one benign failure is the set not existing yet (racy first
		// boot): nft reports "No such file or directory" on STDERR, which
		// cmd.Output captures in ExitError.Stderr. Every other non-zero exit
		// (EPERM, missing CAP_NET_ADMIN, broken table state) must surface —
		// swallowing it makes init/reload log an empty cache and desyncs the
		// helper's blocked cache from the kernel (issue #318).
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && isNftAbsentErr(string(exitErr.Stderr)) {
			return nil, nil
		}
		return nil, fmt.Errorf("nft list set %s: %w", set, err)
	}
	return parseSetElements(out), nil
}

// setElem is one element of a blocked set: the canonical IP/CIDR string plus
// its remaining kernel lifetime. ttl == 0 means permanent (no nft `timeout`).
// The remaining lifetime matters because the kernel expires timed elements on
// its own — a cache that ignores it serves ghosts after expiry (issue #383).
type setElem struct {
	ip  string
	ttl time.Duration
}

// parseSetElements extracts the elements of `nft list set` output.
// It finds the `elements = { ... }` block and parses each comma-separated
// entry as a netip.Addr or netip.Prefix plus its remaining lifetime from the
// `expires` annotation (falling back to `timeout` when nft omits `expires`,
// which it does in the brief window right after an element is added).
func parseSetElements(out []byte) []setElem {
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

	var elems []setElem
	for _, part := range strings.Split(block, ",") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) == 0 {
			continue
		}
		tok := fields[0]
		if _, err := netip.ParseAddr(tok); err == nil {
			elems = append(elems, setElem{ip: tok, ttl: elemTTL(fields[1:])})
			continue
		}
		if pfx, err := netip.ParsePrefix(tok); err == nil {
			elems = append(elems, setElem{ip: pfx.String(), ttl: elemTTL(fields[1:])})
		}
	}
	return elems
}

// elemTTL extracts the remaining lifetime from an element's annotation
// fields (`timeout 24h expires 3h2m11s`). Preference order: `expires`
// (remaining) over `timeout` (original). No annotation → 0 (permanent).
// An annotation that is present but unparseable returns one second: the
// fail-safe direction is treating the element as ABOUT TO EXPIRE — the
// daemon's next Sync then re-adds it — never as permanent, which is exactly
// the ghost-entry failure this parser exists to prevent (issue #383).
func elemTTL(annotations []string) time.Duration {
	dur := func(key string) (time.Duration, bool) {
		for i := 0; i+1 < len(annotations); i++ {
			if annotations[i] != key {
				continue
			}
			d, err := parseNftDuration(annotations[i+1])
			if err != nil {
				return time.Second, true
			}
			return d, true
		}
		return 0, false
	}
	if d, ok := dur("expires"); ok {
		return d
	}
	if d, ok := dur("timeout"); ok {
		return d
	}
	return 0
}

// parseNftDuration parses nft's duration syntax, which is Go's except that it
// also uses `d` for days (`6d23h59m12s`).
func parseNftDuration(s string) (time.Duration, error) {
	var days time.Duration
	if i := strings.IndexByte(s, 'd'); i >= 0 {
		n, err := strconv.ParseUint(s[:i], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("nft duration %q: %w", s, err)
		}
		days = time.Duration(n) * 24 * time.Hour
		s = s[i+1:]
		if s == "" {
			return days, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("nft duration: %w", err)
	}
	return days + d, nil
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
