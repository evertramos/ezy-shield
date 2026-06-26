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
	reSyslogPrefix  = regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(.*)$`)
	reFailedInvalid = regexp.MustCompile(`^Failed \S+ for invalid user (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`)
	reFailedPass    = regexp.MustCompile(`^Failed \S+ for (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`)
	reInvalidUser   = regexp.MustCompile(`^Invalid user (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`)
	reAccepted      = regexp.MustCompile(`^Accepted \S+ for (\S{1,64}) from ([0-9a-fA-F.:]+) port (\d{1,5})`)
)

// SSHParser parses SSH authentication log lines.
// Sources handled: "journald:sshd", "file:/var/log/auth.log", any ending in "auth.log" or "/secure".
type SSHParser struct {
	logger *slog.Logger
}

// NewSSHParser creates an SSHParser that writes debug messages to logger.
func NewSSHParser(logger *slog.Logger) *SSHParser {
	return &SSHParser{logger: logger}
}

// Matches reports whether this parser handles the given collector source ID.
func (p *SSHParser) Matches(source string) bool {
	return source == "journald:sshd" ||
		source == "file:/var/log/auth.log" ||
		strings.HasSuffix(source, "auth.log") ||
		strings.HasSuffix(source, "/secure") ||
		strings.HasPrefix(source, "ssh:")
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

	// Determine event timestamp and message body.
	// Try to strip the syslog prefix first.
	eventTime := line.At
	msg := raw

	if m := reSyslogPrefix.FindStringSubmatch(raw); m != nil {
		stamp := m[1]
		msg = m[2]
		if t, err := parseSSHTime(stamp, line.At); err == nil {
			eventTime = t
		}
		// If timestamp parse fails, fall back to collection time (already set).
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
	if len(username) > maxUsernameBytes {
		username = username[:maxUsernameBytes]
	}
	return map[string]string{
		"username": username,
		"port":     port,
	}
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
