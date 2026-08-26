// SPDX-License-Identifier: AGPL-3.0-only

package parser

// Postfix smtpd parser (issue #188): mail servers are among the most
// brute-forced services. Postfix logs SASL auth failures and relay attempts
// via syslog/journald; parsing them enables ban decisions for SMTP abuse.
//
// Events emitted:
//
//	smtp_auth_fail    — "warning: unknown[IP]: SASL LOGIN authentication failed"
//	smtp_relay_denied — "NOQUEUE: reject: RCPT from x[IP]: 554 ... Relay access denied"
//	smtp_abuse        — "too many errors after RCPT from x[IP]" /
//	                    "lost connection after AUTH from x[IP]"
//
// The hostname before the bracket is spoofable (reverse DNS under the
// client's control) and is deliberately ignored — the bracketed IP is the
// only authoritative identity.

import (
	"log/slog"
	"net/netip"
	"regexp"
	"strings"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// Postfix field caps: attacker-influenced strings stored on events.
const (
	maxPostfixMethodBytes = 32
	maxPostfixUserBytes   = 64
)

// The hostname part before the bracket ("unknown", a spoofable rDNS name)
// is matched loosely and thrown away; only the bracketed address is kept.
var (
	// warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: ...
	rePostfixAuthFail = regexp.MustCompile(
		`warning: [^\s\[]*\[([^\]]+)\]: SASL ([A-Za-z0-9._-]+) authentication failed`)
	// NOQUEUE: reject: RCPT from unknown[203.0.113.5]: 554 5.7.1 ... Relay access denied ...
	rePostfixRelayDenied = regexp.MustCompile(
		`NOQUEUE: reject: RCPT from [^\s\[]*\[([^\]]+)\][:,].*Relay access denied`)
	// too many errors after RCPT from unknown[203.0.113.5]
	rePostfixTooManyErrors = regexp.MustCompile(
		`too many errors after [A-Za-z-]+ from [^\s\[]*\[([^\]]+)\]`)
	// ... lost connection after AUTH from unknown[203.0.113.5]
	rePostfixLostAuth = regexp.MustCompile(
		`lost connection after AUTH from [^\s\[]*\[([^\]]+)\]`)
	// Optional sasl_username=... attribute on reject lines. The value is
	// untrusted attacker input: captured without spaces, capped below.
	rePostfixSASLUser = regexp.MustCompile(`sasl_username=([^\s,]+)`)
)

// PostfixParser parses Postfix smtpd log lines into SMTP abuse Events.
type PostfixParser struct {
	logger *slog.Logger
}

// NewPostfixParser creates a PostfixParser that writes debug messages to logger.
func NewPostfixParser(logger *slog.Logger) *PostfixParser {
	return &PostfixParser{logger: logger}
}

// Matches reports whether this parser handles the given collector source ID.
// Follows the SSH parser's convention: explicit "postfix:" override always
// wins; journald units postfix.service and postfix@<instance>.service are
// claimed; file sources route by the conventional mail log names.
func (p *PostfixParser) Matches(source string) bool {
	if strings.HasPrefix(source, "postfix:") {
		return true
	}
	if unit, ok := strings.CutPrefix(source, "journald:"); ok {
		unit = strings.TrimSuffix(unit, ".service")
		return unit == "postfix" || strings.HasPrefix(unit, "postfix@")
	}
	if path, ok := strings.CutPrefix(source, "file:"); ok {
		return isPostfixLogPath(path)
	}
	if strings.Contains(source, ":") {
		return false // another parser's explicit override
	}
	return isPostfixLogPath(source)
}

// isPostfixLogPath reports whether path is a conventional mail log:
// Debian's mail.log or the RHEL family's maillog.
func isPostfixLogPath(path string) bool {
	return strings.HasSuffix(path, "mail.log") || strings.HasSuffix(path, "/maillog")
}

// Parse converts one raw Postfix log line into zero or one Event. Oversized,
// empty, or unrecognised lines are skipped (debug-logged); malformed input
// never panics or returns a non-nil error.
func (p *PostfixParser) Parse(line sdk.RawLine) ([]sdk.Event, error) {
	if len(line.Line) > maxLineBytes {
		p.logger.Debug("postfix: line exceeds max size, skipping",
			slog.Int("size", len(line.Line)),
			slog.String("source", line.Source),
		)
		return nil, nil
	}
	raw := strings.TrimRight(string(line.Line), "\r\n")
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	// Container setups (mailcow et al) log through docker's json-file
	// driver — unwrap it exactly like the HTTP parsers do (issue #358).
	if raw[0] == '{' {
		if inner := extractDockerLogField(raw); inner != "" {
			raw = strings.TrimRight(inner, "\r\n")
		}
	}

	kind, ipRaw, fields := classifyPostfixLine(raw)
	if kind == "" {
		return nil, nil
	}
	ip, ok := parsePostfixAddr(ipRaw)
	if !ok {
		p.logger.Debug("postfix: invalid client IP",
			slog.String("raw", redactForLog(ipRaw)),
		)
		return nil, nil
	}
	return []sdk.Event{{
		Time:     line.At,
		SourceIP: ip,
		Kind:     kind,
		Fields:   fields,
		Origin:   line.Source,
	}}, nil
}

// classifyPostfixLine matches the known abuse signatures, returning the
// event kind, the raw bracketed address, and the (capped) fields.
func classifyPostfixLine(raw string) (kind, ipRaw string, fields map[string]string) {
	if m := rePostfixAuthFail.FindStringSubmatch(raw); m != nil {
		return "smtp_auth_fail", m[1], map[string]string{
			"method": capField(m[2], maxPostfixMethodBytes),
		}
	}
	if m := rePostfixRelayDenied.FindStringSubmatch(raw); m != nil {
		fields := map[string]string{"reject": "relay"}
		if u := rePostfixSASLUser.FindStringSubmatch(raw); u != nil {
			fields["user"] = capField(u[1], maxPostfixUserBytes)
		}
		return "smtp_relay_denied", m[1], fields
	}
	if m := rePostfixTooManyErrors.FindStringSubmatch(raw); m != nil {
		return "smtp_abuse", m[1], map[string]string{"abuse": "too_many_errors"}
	}
	if m := rePostfixLostAuth.FindStringSubmatch(raw); m != nil {
		return "smtp_abuse", m[1], map[string]string{"abuse": "lost_connection_after_auth"}
	}
	return "", "", nil
}

// parsePostfixAddr parses the bracketed client address. Postfix logs plain
// IPv4/IPv6 forms and (in address-literal style) an "IPv6:" prefix; both are
// accepted, mapped v4-in-v6 normalized via Unmap.
func parsePostfixAddr(s string) (netip.Addr, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "IPv6:")
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// capField bounds an attacker-influenced field value.
func capField(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
