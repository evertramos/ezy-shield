// Package parser provides log parsers that convert raw log lines into structured Events.
package parser

import (
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// maxLineBytes is the hard cap on raw line length; lines larger than this are skipped.
const maxLineBytes = 4096

// maxUsernameBytes is the hard cap on extracted username length.
const maxUsernameBytes = 64

// maxRedactLen is the maximum length of a redacted string used in log messages.
const maxRedactLen = 200

// Canonical SSH event kinds. Recognition is broad (many line variants), but the
// decision surface is deliberately small: only these four kinds exist, and the
// specific line that matched is preserved in Fields["subtype"] for observability
// — not as a distinct kind. See issue #140.
//
//   - kindInvalidUser / kindFail: real authentication attempts. These are the
//     kinds the built-in ban rules count (configs/rules.yaml).
//   - kindProbe: connection/protocol anomalies and corroborating termination /
//     PAM echoes of an attempt already counted. NOT counted by the default
//     rules — available to an opt-in "aggressive" rule (higher false-positive
//     risk on shared/CGNAT IPs).
//   - kindAccept: successful auth. Telemetry only; referenced by no ban rule and
//     never used to suppress strikes (a success is not proof of innocence on a
//     shared IP).
const (
	kindInvalidUser = "ssh_invalid_user"
	kindFail        = "ssh_fail"
	kindAccept      = "ssh_accept"
	kindProbe       = "ssh_probe"
)

// Syslog prefix regexes — compiled once, reused for every parsed line. Both
// capture the sshd PID (group 2) so a future connection-scoped deduplicator can
// key on (IP, pid); journald "-o cat" carries no prefix, so pid is then empty.
var (
	// reSyslogPrefix matches the traditional RFC3164 syslog prefix
	// "Jan  1 12:00:00 host sshd[123]: msg" — RHEL/CentOS /var/log/secure and
	// older distros. Also matches "sshd-session" (OpenSSH 9.6+ split session).
	// Groups: 1=timestamp, 2=pid, 3=message.
	reSyslogPrefix = regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:-session)?\[(\d+)\]:\s+(.*)$`)
	// reSyslogPrefixISO matches the RFC3339/ISO-8601 syslog prefix
	// "2026-07-13T22:57:35.182105+00:00 host sshd-session[123]: msg" — the
	// systemd-journald → rsyslog default on Debian 12+/Ubuntu 24.04+.
	// Groups: 1=timestamp, 2=pid, 3=message.
	reSyslogPrefixISO = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+\S+\s+sshd(?:-session)?\[(\d+)\]:\s+(.*)$`)
)

// sshPattern binds a message regex to the canonical kind it produces and the
// submatch indices for the fields to extract. ipIdx is required (>0); a pattern
// that cannot yield an IP is not attributable and is deliberately omitted (e.g.
// "check pass; user unknown", "ignoring max retries" — no rhost). userIdx and
// portIdx are 0 when absent.
type sshPattern struct {
	re      *regexp.Regexp
	kind    string
	subtype string // fixed internal constant, never attacker-controlled
	userIdx int
	ipIdx   int
	portIdx int
}

// sshPatterns is evaluated top-to-bottom; the first match wins, so more-specific
// patterns MUST precede their looser prefixes (e.g. "... by invalid user X IP"
// before the bare "... by IP"). See issue #140 for the full mapping rationale.
//
// Only the first four (real auth attempts) map to the default-bannable kinds;
// every other recognised line maps to kindProbe so broadening recognition never
// inflates the built-in rule counts.
var sshPatterns = []sshPattern{
	// ---- Authentication attempts (default-bannable) ----
	// "Failed password/none/... for invalid user X from IP port P" — must precede
	// the valid-user variant below.
	{re: regexp.MustCompile(`^Failed \S+ for invalid user (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindInvalidUser, subtype: "failed_invalid", userIdx: 1, ipIdx: 2, portIdx: 3},
	// "Failed password/none/... for X from IP port P" (valid/known user).
	{re: regexp.MustCompile(`^Failed \S+ for (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindFail, subtype: "failed_password", userIdx: 1, ipIdx: 2, portIdx: 3},
	// "Invalid user X from IP port P".
	{re: regexp.MustCompile(`^Invalid user (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindInvalidUser, subtype: "invalid_user", userIdx: 1, ipIdx: 2, portIdx: 3},
	// "User X from IP not allowed because ..." (AllowUsers/DenyUsers). No port.
	{re: regexp.MustCompile(`^User (\S{1,64}) from ([0-9a-fA-F.:]+) not allowed`), kind: kindInvalidUser, subtype: "not_allowed", userIdx: 1, ipIdx: 2, portIdx: 0},

	// ---- Probe / corroboration (opt-in aggressive; not counted by default) ----
	// "error: maximum authentication attempts exceeded for [invalid user] X from IP port P".
	{re: regexp.MustCompile(`^error: maximum authentication attempts exceeded for invalid user (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "max_attempts", userIdx: 1, ipIdx: 2, portIdx: 3},
	{re: regexp.MustCompile(`^error: maximum authentication attempts exceeded for (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "max_attempts", userIdx: 1, ipIdx: 2, portIdx: 3},
	// "ssh_dispatch_run_fatal: Connection from invalid user X IP port P: ...".
	{re: regexp.MustCompile(`^ssh_dispatch_run_fatal: Connection from invalid user (\S{1,64}) ([0-9a-fA-F.:]+) port (\d{1,5}):`), kind: kindProbe, subtype: "dispatch_fatal", userIdx: 1, ipIdx: 2, portIdx: 3},
	// Termination lines naming an invalid user — must precede the bare variants.
	{re: regexp.MustCompile(`^Connection closed by invalid user (\S{1,64}) ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "conn_closed_invalid", userIdx: 1, ipIdx: 2, portIdx: 3},
	{re: regexp.MustCompile(`^Connection reset by invalid user (\S{1,64}) ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "conn_reset_invalid", userIdx: 1, ipIdx: 2, portIdx: 3},
	{re: regexp.MustCompile(`^Disconnected from invalid user (\S{1,64}) ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "disconnected_invalid", userIdx: 1, ipIdx: 2, portIdx: 3},
	{re: regexp.MustCompile(`^Disconnecting invalid user (\S{1,64}) ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "disconnecting_invalid", userIdx: 1, ipIdx: 2, portIdx: 3},
	// Termination lines naming an authenticating (valid/allowed) user.
	{re: regexp.MustCompile(`^Connection closed by authenticating user (\S{1,64}) ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "authenticating_closed", userIdx: 1, ipIdx: 2, portIdx: 3},
	{re: regexp.MustCompile(`^Connection reset by authenticating user (\S{1,64}) ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "authenticating_reset", userIdx: 1, ipIdx: 2, portIdx: 3},
	{re: regexp.MustCompile(`^Disconnected from authenticating user (\S{1,64}) ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "authenticating_disconnected", userIdx: 1, ipIdx: 2, portIdx: 3},
	{re: regexp.MustCompile(`^Disconnecting authenticating user (\S{1,64}) ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "authenticating_disconnecting", userIdx: 1, ipIdx: 2, portIdx: 3},
	// Bare termination lines (no username).
	{re: regexp.MustCompile(`^Connection closed by ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "conn_closed", userIdx: 0, ipIdx: 1, portIdx: 2},
	{re: regexp.MustCompile(`^Connection reset by ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "conn_reset", userIdx: 0, ipIdx: 1, portIdx: 2},
	{re: regexp.MustCompile(`^Received disconnect from ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "disconnect_recv", userIdx: 0, ipIdx: 1, portIdx: 2},
	{re: regexp.MustCompile(`^Disconnected from ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "disconnected", userIdx: 0, ipIdx: 1, portIdx: 2},
	// Protocol-level anomalies carrying an IP.
	{re: regexp.MustCompile(`^banner exchange: Connection from ([0-9a-fA-F.:]+) port (\d{1,5}):`), kind: kindProbe, subtype: "banner_invalid", userIdx: 0, ipIdx: 1, portIdx: 2},
	{re: regexp.MustCompile(`^error: kex_exchange_identification: Connection (?:reset|closed) by ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "kex_reset", userIdx: 0, ipIdx: 1, portIdx: 2},
	{re: regexp.MustCompile(`^Unable to negotiate with ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindProbe, subtype: "negotiate_fail", userIdx: 0, ipIdx: 1, portIdx: 2},
	// PAM auth failures carrying rhost=IP (the "user=" suffix is optional; the
	// username there is not positionally stable, so it is not extracted).
	{re: regexp.MustCompile(`^pam_unix\(sshd:auth\): authentication failure;.*?rhost=([0-9a-fA-F.:]+)`), kind: kindProbe, subtype: "pam_auth_fail", userIdx: 0, ipIdx: 1, portIdx: 0},
	{re: regexp.MustCompile(`^PAM \d+ more authentication failures?;.*?rhost=([0-9a-fA-F.:]+)`), kind: kindProbe, subtype: "pam_more_fail", userIdx: 0, ipIdx: 1, portIdx: 0},

	// ---- Success (telemetry only) ----
	{re: regexp.MustCompile(`^Accepted \S+ for (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`), kind: kindAccept, subtype: "accepted", userIdx: 1, ipIdx: 2, portIdx: 3},
}

// SSHParser parses SSH authentication log lines from any distribution and
// collection method:
//   - journald units: "journald:ssh" (Debian/Ubuntu), "journald:sshd"
//     (RHEL/CentOS/Fedora/Arch/SUSE), "journald:sshd-session", each with or
//     without a ".service" suffix.
//   - file logs: any path ending in "auth.log" (Debian/Ubuntu) or "/secure"
//     (RHEL family), as "file:<path>" or a bare path.
//   - an explicit "ssh:" parser override (parser: ssh in a collector).
//
// Both the RFC3164 ("Jan  1 12:00:00") and RFC3339/ISO-8601
// ("2026-07-13T22:57:35.182105+00:00") syslog prefixes are recognised, as are
// prefix-less messages (journald "-o cat").
type SSHParser struct {
	logger *slog.Logger
}

// NewSSHParser creates an SSHParser that writes debug messages to logger.
func NewSSHParser(logger *slog.Logger) *SSHParser {
	return &SSHParser{logger: logger}
}

// Matches reports whether this parser handles the given collector source ID.
//
// The SSH systemd unit is "ssh" on Debian/Ubuntu but "sshd" on the RHEL family,
// Arch and SUSE; both (and the OpenSSH 9.6+ "sshd-session" identifier) are
// accepted, with or without a ".service" suffix. An explicit override for a
// different parser (e.g. "nginx:<path>") is never claimed, so routing stays
// deterministic.
func (p *SSHParser) Matches(source string) bool {
	// Explicit parser override wins.
	if strings.HasPrefix(source, "ssh:") {
		return true
	}
	// journald unit sources — accept the SSH unit under any distro's name.
	if unit, ok := strings.CutPrefix(source, "journald:"); ok {
		switch strings.TrimSuffix(unit, ".service") {
		case "ssh", "sshd", "sshd-session":
			return true
		default:
			return false
		}
	}
	// Auto-routed file sources ("file:<path>").
	if path, ok := strings.CutPrefix(source, "file:"); ok {
		return isSSHLogPath(path)
	}
	// Any other explicit "<parser>:..." override belongs to that parser.
	if strings.Contains(source, ":") {
		return false
	}
	// Bare path fallback (no scheme).
	return isSSHLogPath(source)
}

// isSSHLogPath reports whether path is a conventional SSH auth log file:
// Debian/Ubuntu "auth.log" or the RHEL family's "/secure".
func isSSHLogPath(path string) bool {
	return strings.HasSuffix(path, "auth.log") || strings.HasSuffix(path, "/secure")
}

// Parse converts a single raw log line into zero or more Events.
// Malformed, oversized, or unrecognised lines are silently skipped (debug-logged).
func (p *SSHParser) Parse(line sdk.RawLine) ([]sdk.Event, error) {
	// Hard cap: skip lines that exceed maxLineBytes.
	if len(line.Line) > maxLineBytes {
		p.logger.Debug("ssh: line exceeds max size, skipping",
			slog.Int("size", len(line.Line)),
			slog.String("source", line.Source),
		)
		return nil, nil
	}

	raw := string(line.Line)
	raw = strings.TrimRight(raw, "\r\n")
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	// Determine event timestamp, connection pid and message body by stripping a
	// syslog prefix, if present. Two prefix formats are supported (ISO-8601
	// first, then the legacy RFC3164 stamp); a prefix-less message (journald
	// "-o cat") falls through unchanged with an empty pid. If timestamp parsing
	// fails, collection time is used.
	eventTime := line.At
	msg := raw
	pid := ""

	if m := reSyslogPrefixISO.FindStringSubmatch(raw); m != nil {
		pid, msg = m[2], m[3]
		if t, err := parseISOTime(m[1]); err == nil {
			eventTime = t
		}
	} else if m := reSyslogPrefix.FindStringSubmatch(raw); m != nil {
		pid, msg = m[2], m[3]
		if t, err := parseSSHTime(m[1], line.At); err == nil {
			eventTime = t
		}
	}

	// Attempt each pattern in order (most specific first).
	ev, ok := p.matchMessage(msg, eventTime, line.Source, pid)
	if !ok {
		p.logger.Debug("ssh: unrecognised message, skipping",
			slog.String("msg", redactForLog(msg)),
		)
		return nil, nil
	}

	return []sdk.Event{ev}, nil
}

// matchMessage applies the SSH message patterns to msg and returns an Event on
// the first match. A matched pattern whose IP fails to parse yields no event
// (the line is malformed); it is not retried against looser patterns.
func (p *SSHParser) matchMessage(msg string, t time.Time, origin, pid string) (sdk.Event, bool) {
	for _, pat := range sshPatterns {
		m := pat.re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		ip, err := parseIP(m[pat.ipIdx])
		if err != nil {
			p.logger.Debug("ssh: invalid IP in matched pattern",
				slog.String("subtype", pat.subtype),
				slog.String("raw", redactForLog(m[pat.ipIdx])),
			)
			return sdk.Event{}, false
		}
		f := map[string]string{"subtype": pat.subtype}
		if pat.userIdx > 0 {
			f["username"] = capUsername(m[pat.userIdx])
		}
		if pat.portIdx > 0 {
			f["port"] = m[pat.portIdx]
		}
		if pid != "" {
			f["pid"] = pid
		}
		return sdk.Event{
			Time:     t,
			SourceIP: ip,
			Kind:     pat.kind,
			Fields:   f,
			Origin:   origin,
		}, true
	}
	return sdk.Event{}, false
}

// capUsername truncates username to maxUsernameBytes.
func capUsername(username string) string {
	if len(username) > maxUsernameBytes {
		return username[:maxUsernameBytes]
	}
	return username
}

// parseIP parses an IP address string, stripping optional brackets (IPv6).
func parseIP(s string) (netip.Addr, error) {
	// Some sshd versions log IPv6 addresses in brackets, e.g. [2001:db8::1].
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parseIP: %w", err)
	}
	return addr, nil
}

// parseISOTime parses an RFC3339/ISO-8601 syslog timestamp, tolerating both
// colon ("+00:00") and bare ("+0000") numeric offsets and optional fractional
// seconds. The timestamp carries its own zone, so no reference time is needed.
func parseISOTime(stamp string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999Z0700"} {
		if t, err := time.Parse(layout, stamp); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("parseISOTime: unrecognized timestamp %q", stamp)
}

// parseSSHTime parses a syslog timestamp (time.Stamp format) relative to a reference time.
// The year is inferred from ref; if the parsed date is more than 24 h in the future,
// the previous year is used (handles log lines at year boundary).
func parseSSHTime(stamp string, ref time.Time) (time.Time, error) {
	t, err := time.ParseInLocation(time.Stamp, stamp, ref.Location())
	if err != nil {
		return time.Time{}, fmt.Errorf("parseSSHTime: %w", err)
	}
	t = time.Date(ref.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, t.Location())
	if t.After(ref.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, nil
}

// redactForLog strips ASCII control characters (< 0x20, except tab) from s and
// caps the result at maxRedactLen characters. Used to safely include attacker-
// controlled strings in log messages.
func redactForLog(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	count := 0
	for _, r := range s {
		if count >= maxRedactLen {
			break
		}
		if r < 0x20 && r != '\t' {
			continue // strip control chars
		}
		b.WriteRune(r)
		count += utf8.RuneLen(r)
	}
	return b.String()
}
