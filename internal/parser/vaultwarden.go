package parser

// Vaultwarden parser (issue #191): a password vault is a prime brute-force
// target (and a top fail2ban recipe). Vaultwarden logs failed logins with
// the source IP in its default LOG format, on file or docker stdout:
//
//	[2026-08-25 14:00:00.123][vaultwarden::api::identity][ERROR]
//	Username or password is incorrect. Try again. IP: 203.0.113.5.
//	Username: user@example.com.
//
// Events emitted: vaultwarden_auth_fail — password failures (with the
// capped username when present) and the 2FA variant ("Invalid TOTP code",
// field mfa=totp) when the line carries an IP.
//
// Reverse-proxy caveat (see the docs guide): when Vaultwarden sits behind
// nginx/caddy/traefik WITHOUT trusted-proxy configuration, the logged IP is
// the proxy's — banning it would be self-inflicted. The right source is
// then the proxy's own access log; only parse Vaultwarden's log when it
// sees real client IPs.

import (
	"log/slog"
	"net/netip"
	"regexp"
	"strings"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// maxVaultwardenUserBytes caps the captured username (untrusted input —
// arbitrary bytes the client typed into the login form).
const maxVaultwardenUserBytes = 64

var (
	// Username or password is incorrect. Try again. IP: 203.0.113.5. Username: user@example.com.
	reVWAuthFail = regexp.MustCompile(
		`Username or password is incorrect\. Try again\. IP: ([0-9a-fA-F:.]+)\.(?: Username: (\S+?)\.?)?$`)
	// Invalid TOTP code! Server time: ... IP: 203.0.113.5
	reVWTotpFail = regexp.MustCompile(
		`Invalid TOTP code!.* IP: ([0-9a-fA-F:.]+)`)
)

// VaultwardenParser parses Vaultwarden log lines into auth-failure Events.
type VaultwardenParser struct {
	logger *slog.Logger
}

// NewVaultwardenParser creates a VaultwardenParser that writes debug
// messages to logger.
func NewVaultwardenParser(logger *slog.Logger) *VaultwardenParser {
	return &VaultwardenParser{logger: logger}
}

// Matches reports whether this parser handles the given collector source ID:
// the explicit "vaultwarden:" override (file or docker collectors), docker
// sources whose container name contains "vaultwarden" (the image's
// conventional name), and vaultwarden.log file sources.
func (p *VaultwardenParser) Matches(source string) bool {
	if strings.HasPrefix(source, "vaultwarden:") {
		return true
	}
	if name, ok := strings.CutPrefix(source, "docker:"); ok {
		return strings.Contains(strings.ToLower(name), "vaultwarden")
	}
	if path, ok := strings.CutPrefix(source, "file:"); ok {
		return strings.HasSuffix(path, "vaultwarden.log")
	}
	if strings.Contains(source, ":") {
		return false // another parser's explicit override
	}
	return strings.HasSuffix(source, "vaultwarden.log")
}

// Parse converts one raw Vaultwarden log line into zero or one Event.
// Oversized, empty, or unrecognised lines are skipped; malformed input
// never panics or returns a non-nil error.
func (p *VaultwardenParser) Parse(line sdk.RawLine) ([]sdk.Event, error) {
	if len(line.Line) > maxLineBytes {
		p.logger.Debug("vaultwarden: line exceeds max size, skipping",
			slog.Int("size", len(line.Line)),
			slog.String("source", line.Source),
		)
		return nil, nil
	}
	raw := strings.TrimRight(string(line.Line), "\r\n")
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	// Docker json-file unwrap, matching the other parsers (issue #358).
	if raw[0] == '{' {
		if inner := extractDockerLogField(raw); inner != "" {
			raw = strings.TrimRight(inner, "\r\n")
		}
	}

	var ipRaw string
	fields := map[string]string{}
	if m := reVWAuthFail.FindStringSubmatch(raw); m != nil {
		ipRaw = m[1]
		if m[2] != "" {
			fields["user"] = capVaultwardenField(m[2], maxVaultwardenUserBytes)
		}
	} else if m := reVWTotpFail.FindStringSubmatch(raw); m != nil {
		ipRaw = m[1]
		fields["mfa"] = "totp"
	} else {
		return nil, nil
	}

	ip, err := netip.ParseAddr(ipRaw)
	if err != nil {
		p.logger.Debug("vaultwarden: invalid IP",
			slog.String("raw", redactForLog(ipRaw)),
		)
		return nil, nil
	}
	return []sdk.Event{{
		Time:     line.At,
		SourceIP: ip.Unmap(),
		Kind:     "vaultwarden_auth_fail",
		Fields:   fields,
		Origin:   line.Source,
	}}, nil
}

// capVaultwardenField bounds an attacker-influenced field value.
func capVaultwardenField(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
