package parser

// Keycloak parser (issue #193): Keycloak (Quarkus) logs login events via
// the org.keycloak.events logger when event logging is enabled (the docs
// guide shows the configuration). LOGIN_ERROR lines carry the client
// address as a key=value attribute:
//
//	... type=LOGIN_ERROR, realmId=master, clientId=account, userId=null,
//	ipAddress=203.0.113.5, error=invalid_user_credentials, username=admin
//
// Extraction is key=value based and order-independent — Keycloak's
// attribute order varies across versions and event listeners.

import (
	"log/slog"
	"net/netip"
	"regexp"
	"strings"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// Keycloak field caps: attacker-influenced strings stored on events.
const (
	maxKeycloakUserBytes  = 64
	maxKeycloakRealmBytes = 64
	maxKeycloakErrorBytes = 64
)

var (
	// reKeycloakType gates on the event type before any other work.
	reKeycloakType = regexp.MustCompile(`\btype="?LOGIN_ERROR"?[,\s]`)
	// Attribute extractors — order-independent, values without spaces
	// (Keycloak logs them comma-separated), optionally quoted.
	reKeycloakIP    = regexp.MustCompile(`\bipAddress="?([0-9a-fA-F:.]+)"?`)
	reKeycloakUser  = regexp.MustCompile(`\busername="?([^,"\s]+)"?`)
	reKeycloakRealm = regexp.MustCompile(`\brealmId="?([^,"\s]+)"?`)
	reKeycloakError = regexp.MustCompile(`\berror="?([^,"\s]+)"?`)
)

// KeycloakParser parses Keycloak event-logger lines into auth-failure
// Events.
type KeycloakParser struct {
	logger *slog.Logger
}

// NewKeycloakParser creates a KeycloakParser that writes debug messages to
// logger.
func NewKeycloakParser(logger *slog.Logger) *KeycloakParser {
	return &KeycloakParser{logger: logger}
}

// Matches reports whether this parser handles the given collector source ID:
// the explicit "keycloak:" override, the keycloak journald unit, docker
// sources whose container name contains "keycloak", and keycloak.log file
// sources.
func (p *KeycloakParser) Matches(source string) bool {
	if strings.HasPrefix(source, "keycloak:") {
		return true
	}
	if unit, ok := strings.CutPrefix(source, "journald:"); ok {
		return strings.TrimSuffix(unit, ".service") == "keycloak"
	}
	if name, ok := strings.CutPrefix(source, "docker:"); ok {
		return strings.Contains(strings.ToLower(name), "keycloak")
	}
	if path, ok := strings.CutPrefix(source, "file:"); ok {
		return strings.HasSuffix(path, "keycloak.log")
	}
	if strings.Contains(source, ":") {
		return false // another parser's explicit override
	}
	return strings.HasSuffix(source, "keycloak.log")
}

// Parse converts one raw Keycloak log line into zero or one Event.
// Oversized, empty, or non-LOGIN_ERROR lines are skipped; malformed input
// never panics or returns a non-nil error.
func (p *KeycloakParser) Parse(line sdk.RawLine) ([]sdk.Event, error) {
	if len(line.Line) > maxLineBytes {
		p.logger.Debug("keycloak: line exceeds max size, skipping",
			slog.Int("size", len(line.Line)),
			slog.String("source", line.Source),
		)
		return nil, nil
	}
	raw := strings.TrimRight(string(line.Line), "\r\n")
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	// Docker json-file unwrap for containerized Keycloak (issue #358).
	if raw[0] == '{' {
		if inner := extractDockerLogField(raw); inner != "" {
			raw = strings.TrimRight(inner, "\r\n")
		}
	}

	if !reKeycloakType.MatchString(raw + " ") {
		return nil, nil // only LOGIN_ERROR events; LOGIN/CODE_TO_TOKEN stay silent
	}
	ipm := reKeycloakIP.FindStringSubmatch(raw)
	if ipm == nil {
		return nil, nil // no address attribute — nothing to attribute
	}
	ip, err := netip.ParseAddr(ipm[1])
	if err != nil {
		p.logger.Debug("keycloak: invalid ipAddress",
			slog.String("raw", redactForLog(ipm[1])),
		)
		return nil, nil
	}

	fields := map[string]string{}
	if m := reKeycloakUser.FindStringSubmatch(raw); m != nil && m[1] != "null" {
		fields["user"] = capKeycloakField(m[1], maxKeycloakUserBytes)
	}
	if m := reKeycloakRealm.FindStringSubmatch(raw); m != nil {
		fields["realm"] = capKeycloakField(m[1], maxKeycloakRealmBytes)
	}
	if m := reKeycloakError.FindStringSubmatch(raw); m != nil {
		fields["error"] = capKeycloakField(m[1], maxKeycloakErrorBytes)
	}
	return []sdk.Event{{
		Time:     line.At,
		SourceIP: ip.Unmap(),
		Kind:     "keycloak_auth_fail",
		Fields:   fields,
		Origin:   line.Source,
	}}, nil
}

// capKeycloakField bounds an attacker-influenced field value.
func capKeycloakField(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
