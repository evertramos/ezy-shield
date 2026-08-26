package parser

// Dovecot IMAP/POP3 parser (issue #189): Dovecot exposes login brute force
// via journald/syslog lines from its imap-login/pop3-login processes. The
// authoritative identity is the rip= (remote IP) attribute; lip= (local IP)
// is ignored, as is everything else the client can influence beyond capped
// fields.
//
// Events emitted:
//
//	imap_auth_fail — "(auth failed, N attempts in Ns)" aborted/disconnected
//	                 logins (protocol recorded in the "proto" field:
//	                 imap or pop3)
//	imap_probe     — "Disconnected (no auth attempts ...)": connection
//	                 probing with no credentials — a DISTINCT, lower-signal
//	                 kind so rules can weigh it separately.

import (
	"log/slog"
	"net/netip"
	"regexp"
	"strings"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// Dovecot field caps: attacker-influenced strings stored on events.
const (
	maxDovecotUserBytes   = 64
	maxDovecotMethodBytes = 32
)

var (
	// dovecot: imap-login: Aborted login (auth failed, 3 attempts in 6 secs): user=<admin>, method=PLAIN, rip=203.0.113.5, lip=...
	// dovecot: pop3-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<root>, method=PLAIN, rip=203.0.113.5, ...
	reDovecotAuthFail = regexp.MustCompile(
		`(imap|pop3)-login: (?:Aborted login|Disconnected)[^:]*\(auth failed, (\d+) attempts?[^)]*\)`)
	// dovecot: imap-login: Disconnected (no auth attempts in 5 secs): rip=203.0.113.6, ...
	reDovecotNoAuth = regexp.MustCompile(
		`(imap|pop3)-login: Disconnected \(no auth attempts[^)]*\)`)
	// Attributes on the same line. rip is the ONLY identity used; user and
	// method are untrusted attacker input, captured without delimiters and
	// capped below.
	reDovecotRIP    = regexp.MustCompile(`\brip=([0-9a-fA-F:.]+)`)
	reDovecotUser   = regexp.MustCompile(`\buser=<([^>]*)>`)
	reDovecotMethod = regexp.MustCompile(`\bmethod=([A-Za-z0-9._-]+)`)
)

// DovecotParser parses Dovecot login-process log lines into IMAP/POP3
// abuse Events.
type DovecotParser struct {
	logger *slog.Logger
}

// NewDovecotParser creates a DovecotParser that writes debug messages to logger.
func NewDovecotParser(logger *slog.Logger) *DovecotParser {
	return &DovecotParser{logger: logger}
}

// Matches reports whether this parser handles the given collector source ID.
//
// Claimed: the explicit "dovecot:" override, the dovecot journald unit, and
// dovecot.log file sources. Deliberately NOT claimed: the shared mail.log —
// parser routing is first-match and mail.log belongs to the postfix parser
// (issue #188); on hosts where Dovecot logs into the shared mail log, use
// the journald unit (the recommended source) or an explicit
// `parser: dovecot` collector.
func (p *DovecotParser) Matches(source string) bool {
	if strings.HasPrefix(source, "dovecot:") {
		return true
	}
	if unit, ok := strings.CutPrefix(source, "journald:"); ok {
		return strings.TrimSuffix(unit, ".service") == "dovecot"
	}
	if path, ok := strings.CutPrefix(source, "file:"); ok {
		return isDovecotLogPath(path)
	}
	if strings.Contains(source, ":") {
		return false // another parser's explicit override
	}
	return isDovecotLogPath(source)
}

// isDovecotLogPath reports whether path is a dedicated dovecot log file
// (log_path = /var/log/dovecot.log style setups).
func isDovecotLogPath(path string) bool {
	return strings.HasSuffix(path, "dovecot.log")
}

// Parse converts one raw Dovecot log line into zero or one Event.
// Oversized, empty, or unrecognised lines are skipped (debug-logged);
// malformed input never panics or returns a non-nil error.
func (p *DovecotParser) Parse(line sdk.RawLine) ([]sdk.Event, error) {
	if len(line.Line) > maxLineBytes {
		p.logger.Debug("dovecot: line exceeds max size, skipping",
			slog.Int("size", len(line.Line)),
			slog.String("source", line.Source),
		)
		return nil, nil
	}
	raw := strings.TrimRight(string(line.Line), "\r\n")
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	// Container mail stacks log through docker's json-file driver — unwrap
	// exactly like the HTTP parsers (issue #358).
	if raw[0] == '{' {
		if inner := extractDockerLogField(raw); inner != "" {
			raw = strings.TrimRight(inner, "\r\n")
		}
	}

	kind, fields := classifyDovecotLine(raw)
	if kind == "" {
		return nil, nil
	}
	rip := reDovecotRIP.FindStringSubmatch(raw)
	if rip == nil {
		return nil, nil // no remote IP attribute — nothing to attribute
	}
	ip, err := netip.ParseAddr(rip[1])
	if err != nil {
		p.logger.Debug("dovecot: invalid rip",
			slog.String("raw", redactForLog(rip[1])),
		)
		return nil, nil
	}
	return []sdk.Event{{
		Time:     line.At,
		SourceIP: ip.Unmap(),
		Kind:     kind,
		Fields:   fields,
		Origin:   line.Source,
	}}, nil
}

// classifyDovecotLine matches the login-abuse signatures and collects the
// capped fields.
func classifyDovecotLine(raw string) (kind string, fields map[string]string) {
	if m := reDovecotAuthFail.FindStringSubmatch(raw); m != nil {
		fields = map[string]string{
			"proto":    m[1],
			"attempts": m[2],
		}
		if u := reDovecotUser.FindStringSubmatch(raw); u != nil && u[1] != "" {
			fields["user"] = capDovecotField(u[1], maxDovecotUserBytes)
		}
		if me := reDovecotMethod.FindStringSubmatch(raw); me != nil {
			fields["method"] = capDovecotField(me[1], maxDovecotMethodBytes)
		}
		return "imap_auth_fail", fields
	}
	if m := reDovecotNoAuth.FindStringSubmatch(raw); m != nil {
		return "imap_probe", map[string]string{"proto": m[1]}
	}
	return "", nil
}

// capDovecotField bounds an attacker-influenced field value.
func capDovecotField(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
