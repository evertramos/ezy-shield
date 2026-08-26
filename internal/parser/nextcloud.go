package parser

// Nextcloud parser (issue #192): Nextcloud writes structured JSON to
// nextcloud.log, including failed logins with the client address in
// remoteAddr. Relevant entries carry app "core" (message "Login failed:
// 'user' (Remote IP: '…')") and the admin_audit app's login_failed lines.
//
// remoteAddr caveat (documented in the guide): remoteAddr is the CLIENT
// address only when Nextcloud's own trusted_proxies is configured for the
// reverse proxy in front of it; otherwise every failure appears to come
// from the proxy. Configure trusted_proxies in Nextcloud — this parser
// takes remoteAddr as authoritative, exactly as Nextcloud presents it.

import (
	"encoding/json"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// maxNextcloudUserBytes caps the captured username (untrusted input typed
// into the login form).
const maxNextcloudUserBytes = 64

// nextcloudEntry is the strict subset of a nextcloud.log JSON line this
// parser reads; every other field is ignored by encoding/json.
type nextcloudEntry struct {
	RemoteAddr string `json:"remoteAddr"`
	App        string `json:"app"`
	Message    string `json:"message"`
}

// reNextcloudLoginFailed extracts the attempted username from the core
// message form: Login failed: 'admin' (Remote IP: '203.0.113.5')
var reNextcloudLoginFailed = regexp.MustCompile(`^Login failed: '(.*?)'`)

// NextcloudParser parses nextcloud.log JSON lines into auth-failure Events.
type NextcloudParser struct {
	logger *slog.Logger
}

// NewNextcloudParser creates a NextcloudParser that writes debug messages
// to logger.
func NewNextcloudParser(logger *slog.Logger) *NextcloudParser {
	return &NextcloudParser{logger: logger}
}

// Matches reports whether this parser handles the given collector source ID:
// the explicit "nextcloud:" override, docker sources whose container name
// contains "nextcloud", and nextcloud.log file sources.
func (p *NextcloudParser) Matches(source string) bool {
	if strings.HasPrefix(source, "nextcloud:") {
		return true
	}
	if name, ok := strings.CutPrefix(source, "docker:"); ok {
		return strings.Contains(strings.ToLower(name), "nextcloud")
	}
	if path, ok := strings.CutPrefix(source, "file:"); ok {
		return strings.HasSuffix(path, "nextcloud.log")
	}
	if strings.Contains(source, ":") {
		return false // another parser's explicit override
	}
	return strings.HasSuffix(source, "nextcloud.log")
}

// Parse converts one nextcloud.log JSON line into zero or one Event.
// Malformed JSON, oversized lines, and unrelated entries are skipped
// safely; hostile input never panics or returns a non-nil error.
func (p *NextcloudParser) Parse(line sdk.RawLine) ([]sdk.Event, error) {
	// The 4KB line cap bounds the JSON size (and therefore decode work)
	// BEFORE any parsing happens.
	if len(line.Line) > maxLineBytes {
		p.logger.Debug("nextcloud: line exceeds max size, skipping",
			slog.Int("size", len(line.Line)),
			slog.String("source", line.Source),
		)
		return nil, nil
	}
	raw := strings.TrimSpace(strings.TrimRight(string(line.Line), "\r\n"))
	if raw == "" || raw[0] != '{' {
		return nil, nil
	}
	// Docker json-file wrapping: the inner "log" field holds the actual
	// nextcloud.log JSON line (issue #358).
	if inner := extractDockerLogField(raw); inner != "" {
		raw = strings.TrimSpace(strings.TrimRight(inner, "\r\n"))
		if raw == "" || raw[0] != '{' {
			return nil, nil
		}
	}

	var entry nextcloudEntry
	if err := json.Unmarshal([]byte(raw), &entry); err != nil {
		return nil, nil // malformed JSON — skip, never fatal
	}
	if !isNextcloudLoginFailure(entry) {
		return nil, nil
	}
	ip, err := netip.ParseAddr(entry.RemoteAddr)
	if err != nil {
		p.logger.Debug("nextcloud: invalid remoteAddr",
			slog.String("raw", redactForLog(entry.RemoteAddr)),
		)
		return nil, nil
	}

	fields := map[string]string{}
	if m := reNextcloudLoginFailed.FindStringSubmatch(entry.Message); m != nil && m[1] != "" {
		fields["user"] = capNextcloudField(m[1], maxNextcloudUserBytes)
	}
	return []sdk.Event{{
		Time:     line.At,
		SourceIP: ip.Unmap(),
		Kind:     "nextcloud_auth_fail",
		Fields:   fields,
		Origin:   line.Source,
	}}, nil
}

// isNextcloudLoginFailure recognizes the two failure shapes: core's
// "Login failed: …" message and admin_audit's login_failed entries.
func isNextcloudLoginFailure(e nextcloudEntry) bool {
	switch e.App {
	case "core":
		return strings.HasPrefix(e.Message, "Login failed:")
	case "admin_audit":
		return strings.HasPrefix(e.Message, "Login failed:") ||
			strings.Contains(e.Message, "Login attempt failed")
	}
	return false
}

// capNextcloudField bounds an attacker-influenced field value.
func capNextcloudField(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
