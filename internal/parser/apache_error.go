package parser

import (
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// maxApacheMsgBytes caps the parsed Apache error message field. Apache messages
// frequently embed attacker-controlled paths/UAs; storing them unbounded would
// let a hostile request inflate downstream storage and AI prompt costs.
const maxApacheMsgBytes = 512

// reApacheError matches Apache 2.2 and 2.4 error log lines:
//
//	[Fri Jun 26 19:00:00.123456 2026] [core:error] [pid 1234] [client 203.0.113.1:5678] AH00124: ...
//	[Fri Jun 26 19:00:00 2026] [error] [client 203.0.113.1] message
//
// Group 1: "module:level" (2.4) or just "level" (2.2).
// Group 2: raw client field; IP extracted later by parseApacheClientField.
// Group 3: optional trailing message body.
var reApacheError = regexp.MustCompile(
	`^\[[^\]]+\]\s+\[([^\]]+)\]\s+(?:\[pid[^\]]+\]\s+)?\[client\s+(.+?)\](?:\s+(.*))?$`,
)

// reApacheCode peels the leading "AHnnnnn:" tag (Apache 2.4 module codes) off
// the message body so it can be stored in its own field.
var reApacheCode = regexp.MustCompile(`^(AH\d+):\s*(.*)$`)

// ApacheErrorParser parses Apache HTTP Server error_log lines into
// "http_error" Events.
//
// Sources handled: any source prefixed "apache-error:", and well-known Apache
// error_log paths ("/apache2/error" or "/httpd/error" substring).
type ApacheErrorParser struct {
	logger *slog.Logger
}

// NewApacheErrorParser creates an ApacheErrorParser that writes debug messages
// to logger.
func NewApacheErrorParser(logger *slog.Logger) *ApacheErrorParser {
	return &ApacheErrorParser{logger: logger}
}

// Matches reports whether this parser handles the given collector source ID.
func (p *ApacheErrorParser) Matches(source string) bool {
	return strings.HasPrefix(source, "apache-error:") ||
		strings.Contains(source, "/apache2/error") ||
		strings.Contains(source, "/httpd/error")
}

// Parse converts a single raw Apache error log line into zero or one Event.
// Oversized, empty, or unrecognised lines are silently skipped (debug-logged);
// malformed input never panics or returns a non-nil error.
func (p *ApacheErrorParser) Parse(line sdk.RawLine) ([]sdk.Event, error) {
	if len(line.Line) > maxLineBytes {
		p.logger.Debug("apache-error: line exceeds max size, skipping",
			slog.Int("size", len(line.Line)),
			slog.String("source", line.Source),
		)
		return nil, nil
	}

	raw := strings.TrimRight(string(line.Line), "\r\n")
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	m := reApacheError.FindStringSubmatch(raw)
	if m == nil {
		p.logger.Debug("apache-error: unrecognised line, skipping",
			slog.String("line", redactForLog(raw)),
		)
		return nil, nil
	}

	infoRaw := m[1]
	clientRaw := m[2]
	msgRaw := m[3]

	ip, err := parseApacheClientField(clientRaw)
	if err != nil {
		p.logger.Debug("apache-error: invalid client IP",
			slog.String("raw", redactForLog(clientRaw)),
		)
		return nil, nil
	}

	module, level := splitApacheInfo(infoRaw)
	code, msg := splitApacheCode(msgRaw)

	if len(msg) > maxApacheMsgBytes {
		msg = msg[:maxApacheMsgBytes]
	}

	return []sdk.Event{{
		Time:     line.At,
		SourceIP: ip,
		Kind:     "http_error",
		Fields: map[string]string{
			"module": module,
			"level":  level,
			"code":   code,
			"msg":    msg,
		},
		Origin: line.Source,
	}}, nil
}

// splitApacheInfo splits "module:level" (Apache 2.4) into (module, level).
// For the 2.2 single-token form, module is "" and level is the whole string.
func splitApacheInfo(info string) (module, level string) {
	if i := strings.IndexByte(info, ':'); i >= 0 {
		return info[:i], info[i+1:]
	}
	return "", info
}

// splitApacheCode peels a leading "AHnnnnn:" code off msg. Returns ("", msg)
// when no code prefix is present.
func splitApacheCode(msg string) (code, body string) {
	if m := reApacheCode.FindStringSubmatch(msg); m != nil {
		return m[1], m[2]
	}
	return "", msg
}

// parseApacheClientField extracts the client IP from the raw "[client …]"
// payload. Supported forms:
//
//	"192.0.2.1"           plain IPv4
//	"192.0.2.1:5678"      IPv4 with port
//	"2001:db8::1"         legacy IPv6 (no brackets, no port)
//	"[2001:db8::1]:5678"  IPv6 with port (Apache 2.4 default)
func parseApacheClientField(s string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a, nil
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 1 {
			return parseIP(s[1:end])
		}
	}
	if colon := strings.LastIndex(s, ":"); colon > 0 {
		return parseIP(s[:colon])
	}
	return netip.Addr{}, fmt.Errorf("apache: cannot parse client field %q", redactForLog(s))
}
