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

// Package-level compiled regexes — compiled once, reused for every parsed line.
var (
	// reSyslogPrefix matches the traditional RFC3164 syslog prefix
	// "Jan  1 12:00:00 host sshd[123]: msg" — RHEL/CentOS /var/log/secure and
	// older distros. Also matches "sshd-session" (OpenSSH 9.6+ split session).
	reSyslogPrefix = regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+(.*)$`)
	// reSyslogPrefixISO matches the RFC3339/ISO-8601 syslog prefix
	// "2026-07-13T22:57:35.182105+00:00 host sshd-session[123]: msg" — the
	// systemd-journald → rsyslog default on Debian 12+/Ubuntu 24.04+.
	reSyslogPrefixISO = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+(.*)$`)
	reFailedInvalid   = regexp.MustCompile(`^Failed \S+ for invalid user (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`)
	reFailedPass      = regexp.MustCompile(`^Failed \S+ for (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`)
	reInvalidUser     = regexp.MustCompile(`^Invalid user (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`)
	reNotAllowed      = regexp.MustCompile(`^User (\S{1,64}) from ([0-9a-fA-F.:]+) not allowed`)
	reAccepted        = regexp.MustCompile(`^Accepted \S+ for (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`)
	// Connection closed by invalid user (OpenSSH variant)
	reConnectionClosed = regexp.MustCompile(`^Connection closed by invalid user (\S{1,64}) ([0-9a-fA-F.:]+) port (\d{1,5})`)
	// SSH dispatch fatal (connection from invalid user)
	reDispatchFatal = regexp.MustCompile(`^ssh_dispatch_run_fatal: Connection from invalid user (\S{1,64}) ([0-9a-fA-F.:]+) port (\d{1,5}):`)
	// Banner exchange error (protocol-level, no username)
	reBannerError = regexp.MustCompile(`^banner exchange: Connection from ([0-9a-fA-F.:]+) port (\d{1,5}):`)
)

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

	// Determine event timestamp and message body by stripping a syslog prefix,
	// if present. Two prefix formats are supported (ISO-8601 first, then the
	// legacy RFC3164 stamp); a prefix-less message (journald "-o cat") falls
	// through unchanged. If timestamp parsing fails, collection time is used.
	eventTime := line.At
	msg := raw

	if m := reSyslogPrefixISO.FindStringSubmatch(raw); m != nil {
		msg = m[2]
		if t, err := parseISOTime(m[1]); err == nil {
			eventTime = t
		}
	} else if m := reSyslogPrefix.FindStringSubmatch(raw); m != nil {
		msg = m[2]
		if t, err := parseSSHTime(m[1], line.At); err == nil {
			eventTime = t
		}
	}

	// Attempt each pattern in order (most specific first).
	ev, ok := p.matchMessage(msg, eventTime, line.Source)
	if !ok {
		p.logger.Debug("ssh: unrecognised message, skipping",
			slog.String("msg", redactForLog(msg)),
		)
		return nil, nil
	}

	return []sdk.Event{ev}, nil
}

// matchMessage applies the SSH message patterns to msg and returns an Event on success.
func (p *SSHParser) matchMessage(msg string, t time.Time, origin string) (sdk.Event, bool) {
	// reFailedInvalid must be checked before reFailedPass (more specific).
	if m := reFailedInvalid.FindStringSubmatch(msg); m != nil {
		ip, err := parseIP(m[2])
		if err != nil {
			p.logger.Debug("ssh: invalid IP in FailedInvalid", slog.String("raw", redactForLog(m[2])))
			return sdk.Event{}, false
		}
		return sdk.Event{
			Time:     t,
			SourceIP: ip,
			Kind:     "ssh_invalid_user",
			Fields:   fields(m[1], m[3]),
			Origin:   origin,
		}, true
	}

	if m := reFailedPass.FindStringSubmatch(msg); m != nil {
		ip, err := parseIP(m[2])
		if err != nil {
			p.logger.Debug("ssh: invalid IP in FailedPass", slog.String("raw", redactForLog(m[2])))
			return sdk.Event{}, false
		}
		return sdk.Event{
			Time:     t,
			SourceIP: ip,
			Kind:     "ssh_fail",
			Fields:   fields(m[1], m[3]),
			Origin:   origin,
		}, true
	}

	if m := reInvalidUser.FindStringSubmatch(msg); m != nil {
		ip, err := parseIP(m[2])
		if err != nil {
			p.logger.Debug("ssh: invalid IP in InvalidUser", slog.String("raw", redactForLog(m[2])))
			return sdk.Event{}, false
		}
		return sdk.Event{
			Time:     t,
			SourceIP: ip,
			Kind:     "ssh_invalid_user",
			Fields:   fields(m[1], m[3]),
			Origin:   origin,
		}, true
	}

	// "User X from IP not allowed because not listed in AllowUsers" (and similar)
	if m := reNotAllowed.FindStringSubmatch(msg); m != nil {
		ip, err := parseIP(m[2])
		if err != nil {
			p.logger.Debug("ssh: invalid IP in NotAllowed", slog.String("raw", redactForLog(m[2])))
			return sdk.Event{}, false
		}
		return sdk.Event{
			Time:     t,
			SourceIP: ip,
			Kind:     "ssh_invalid_user",
			Fields:   map[string]string{"username": capUsername(m[1])},
			Origin:   origin,
		}, true
	}

	// "Connection closed by invalid user X IP port Y" (OpenSSH variant)
	if m := reConnectionClosed.FindStringSubmatch(msg); m != nil {
		ip, err := parseIP(m[2])
		if err != nil {
			p.logger.Debug("ssh: invalid IP in ConnectionClosed", slog.String("raw", redactForLog(m[2])))
			return sdk.Event{}, false
		}
		return sdk.Event{
			Time:     t,
			SourceIP: ip,
			Kind:     "ssh_invalid_user",
			Fields:   fields(m[1], m[3]),
			Origin:   origin,
		}, true
	}

	// "ssh_dispatch_run_fatal: Connection from invalid user X IP port Y: ..." (fatal dispatch error)
	if m := reDispatchFatal.FindStringSubmatch(msg); m != nil {
		ip, err := parseIP(m[2])
		if err != nil {
			p.logger.Debug("ssh: invalid IP in DispatchFatal", slog.String("raw", redactForLog(m[2])))
			return sdk.Event{}, false
		}
		return sdk.Event{
			Time:     t,
			SourceIP: ip,
			Kind:     "ssh_invalid_user",
			Fields:   fields(m[1], m[3]),
			Origin:   origin,
		}, true
	}

	// "banner exchange: Connection from IP port P: invalid format" (protocol error, no username)
	if m := reBannerError.FindStringSubmatch(msg); m != nil {
		ip, err := parseIP(m[1])
		if err != nil {
			p.logger.Debug("ssh: invalid IP in BannerError", slog.String("raw", redactForLog(m[1])))
			return sdk.Event{}, false
		}
		return sdk.Event{
			Time:     t,
			SourceIP: ip,
			Kind:     "ssh_banner_error",
			Fields:   map[string]string{"port": m[2]},
			Origin:   origin,
		}, true
	}

	if m := reAccepted.FindStringSubmatch(msg); m != nil {
		ip, err := parseIP(m[2])
		if err != nil {
			p.logger.Debug("ssh: invalid IP in Accepted", slog.String("raw", redactForLog(m[2])))
			return sdk.Event{}, false
		}
		return sdk.Event{
			Time:     t,
			SourceIP: ip,
			Kind:     "ssh_accept",
			Fields:   fields(m[1], m[3]),
			Origin:   origin,
		}, true
	}

	return sdk.Event{}, false
}

// fields builds the event Fields map, capping username at maxUsernameBytes.
func fields(username, port string) map[string]string {
	return map[string]string{
		"username": capUsername(username),
		"port":     port,
	}
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
