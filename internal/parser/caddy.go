package parser

import (
	"encoding/json"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// CaddyParser-specific field length caps. The maxLineBytes / maxMethodBytes /
// maxPathBytes / maxUABytes caps are shared with the other parsers and declared
// in nginx.go and ssh.go; only the Caddy-only cap lives here.
const maxHostBytes = 256

// reCaddyCLF matches Caddy's Common Log Format (Apache common, no UA/referer):
//
//	<ip> - <user> [<time>] "<method> <uri> <proto>" <status> <bytes>
//
// Capture groups: 1=ip 2=method 3=uri 4=status 5=bytes
var reCaddyCLF = regexp.MustCompile(
	`^(\S+)\s+-\s+\S+\s+\[[^\]]+\]\s+"([A-Z]{1,16})\s+(\S+)\s+\S+"\s+(\d{1,3})\s+(\d+|-)`,
)

// CaddyConfig holds optional configuration for CaddyParser.
type CaddyConfig struct {
	// TrustedProxies lists CIDR ranges whose connecting IP may be overridden
	// by the X-Forwarded-For header. Empty means XFF is never trusted.
	TrustedProxies []netip.Prefix
}

// CaddyParser parses Caddy v2 access log lines in JSON (primary) or CLF format.
// It implements sdk.Parser.
//
// Sources handled: "journald:caddy", any source path containing "/caddy/",
// any source prefixed with "caddy:".
type CaddyParser struct {
	logger         *slog.Logger
	trustedProxies []netip.Prefix
}

// NewCaddyParser creates a CaddyParser that writes debug messages to logger.
func NewCaddyParser(logger *slog.Logger, cfg CaddyConfig) *CaddyParser {
	return &CaddyParser{
		logger:         logger,
		trustedProxies: cfg.TrustedProxies,
	}
}

// Matches reports whether this parser handles the given collector source ID.
func (p *CaddyParser) Matches(source string) bool {
	return source == "journald:caddy" ||
		strings.Contains(source, "/caddy/") ||
		strings.HasPrefix(source, "caddy:")
}

// Parse converts a single raw log line into zero or more http_request Events.
// Lines that are oversized, empty, or unrecognised are silently skipped (debug-logged).
// Malformed lines never panic or return a non-nil error.
func (p *CaddyParser) Parse(line sdk.RawLine) ([]sdk.Event, error) {
	if len(line.Line) > maxLineBytes {
		p.logger.Debug("caddy: line exceeds max size, skipping",
			slog.Int("size", len(line.Line)),
			slog.String("source", line.Source),
		)
		return nil, nil
	}

	raw := strings.TrimRight(string(line.Line), "\r\n")
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	// Unwrap Docker json-file log format: {"log":"actual line\n","stream":"...","time":"..."}
	if len(raw) > 0 && raw[0] == '{' {
		if inner := extractDockerLogField(raw); inner != "" {
			raw = strings.TrimRight(inner, "\r\n")
		}
	}

	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	var (
		ev sdk.Event
		ok bool
	)

	if len(raw) > 0 && raw[0] == '{' {
		ev, ok = p.parseJSON(raw, line.At, line.Source)
	} else {
		ev, ok = p.parseCLF(raw, line.At, line.Source)
	}

	if !ok {
		p.logger.Debug("caddy: unrecognised line, skipping",
			slog.String("line", redactForLog(raw)),
		)
		return nil, nil
	}

	return []sdk.Event{ev}, nil
}

// parseCLF handles Caddy's Common Log Format (Apache common, no UA/referer).
func (p *CaddyParser) parseCLF(raw string, at time.Time, origin string) (sdk.Event, bool) {
	m := reCaddyCLF.FindStringSubmatch(raw)
	if m == nil {
		return sdk.Event{}, false
	}
	ip, err := parseIP(m[1])
	if err != nil {
		p.logger.Debug("caddy: invalid IP in CLF line",
			slog.String("raw", redactForLog(m[1])),
		)
		return sdk.Event{}, false
	}
	return sdk.Event{
		Time:     at,
		SourceIP: ip,
		Kind:     "http_request",
		Fields:   caddyFields(m[2], m[3], m[4], m[5], "", "", ""),
		Origin:   origin,
	}, true
}

// parseJSON handles Caddy v2 JSON access logs. Top-level fields used:
//
//	request.remote_ip, request.method, request.uri, request.host,
//	request.headers["User-Agent"], request.headers["X-Forwarded-For"],
//	status, size, duration
func (p *CaddyParser) parseJSON(raw string, at time.Time, origin string) (sdk.Event, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return sdk.Event{}, false
	}

	reqRaw, ok := obj["request"]
	if !ok {
		return sdk.Event{}, false
	}
	var req map[string]json.RawMessage
	if err := json.Unmarshal(reqRaw, &req); err != nil {
		return sdk.Event{}, false
	}

	remoteIP := jsonString(req, "remote_ip")
	if remoteIP == "" {
		return sdk.Event{}, false
	}

	ip, err := parseIP(remoteIP)
	if err != nil {
		p.logger.Debug("caddy: invalid remote_ip in JSON line",
			slog.String("raw", redactForLog(remoteIP)),
		)
		return sdk.Event{}, false
	}

	ua, xff := extractCaddyHeaders(req)
	ip = p.resolveXFF(ip, xff)

	method := jsonString(req, "method")
	path := jsonString(req, "uri")
	host := jsonString(req, "host")

	status := jsonString(obj, "status")
	bytesSent := jsonString(obj, "size")
	duration := jsonString(obj, "duration")

	return sdk.Event{
		Time:     at,
		SourceIP: ip,
		Kind:     "http_request",
		Fields:   caddyFields(method, path, status, bytesSent, ua, host, duration),
		Origin:   origin,
	}, true
}

// extractCaddyHeaders returns User-Agent and X-Forwarded-For from a Caddy
// request's "headers" object. Header values are HTTP-style arrays of strings;
// the first array element is used. Canonical casing is tried first, then
// lowercase, since some Caddy configs preserve non-canonical names.
func extractCaddyHeaders(req map[string]json.RawMessage) (ua, xff string) {
	headersRaw, ok := req["headers"]
	if !ok {
		return "", ""
	}
	var headers map[string]json.RawMessage
	if err := json.Unmarshal(headersRaw, &headers); err != nil {
		return "", ""
	}
	ua = headerFirstString(headers, "User-Agent", "user-agent")
	xff = headerFirstString(headers, "X-Forwarded-For", "x-forwarded-for")
	return ua, xff
}

// headerFirstString returns the first value of the first matching header name.
// Values are typically JSON arrays of strings; a bare string is also tolerated.
func headerFirstString(headers map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		v, ok := headers[k]
		if !ok {
			continue
		}
		var arr []string
		if err := json.Unmarshal(v, &arr); err == nil && len(arr) > 0 {
			return arr[0]
		}
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			return s
		}
	}
	return ""
}

// resolveXFF returns the effective client IP. If ip is a trusted proxy and xff
// contains a routable non-trusted address, that address is returned instead.
// Falls back to ip on any resolution failure.
func (p *CaddyParser) resolveXFF(ip netip.Addr, xff string) netip.Addr {
	if xff == "" || xff == "-" || len(p.trustedProxies) == 0 {
		return ip
	}
	if !p.isTrustedProxy(ip) {
		return ip
	}
	for _, part := range strings.Split(xff, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "-" {
			continue
		}
		cand, err := parseIP(part)
		if err != nil {
			continue
		}
		if !p.isTrustedProxy(cand) {
			return cand
		}
	}
	p.logger.Debug("caddy: no untrusted IP in XFF, using remote_ip",
		slog.String("xff", redactForLog(xff)),
	)
	return ip
}

// isTrustedProxy reports whether ip falls within any configured trusted prefix.
func (p *CaddyParser) isTrustedProxy(ip netip.Addr) bool {
	for _, prefix := range p.trustedProxies {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// caddyFields constructs the Event.Fields map, capping each value at its maximum length.
func caddyFields(method, path, status, bytesSent, ua, host, duration string) map[string]string {
	if len(method) > maxMethodBytes {
		method = method[:maxMethodBytes]
	}
	if len(path) > maxPathBytes {
		path = path[:maxPathBytes]
	}
	if len(ua) > maxUABytes {
		ua = ua[:maxUABytes]
	}
	if len(host) > maxHostBytes {
		host = host[:maxHostBytes]
	}
	return map[string]string{
		"method":   method,
		"path":     path,
		"status":   status,
		"bytes":    bytesSent,
		"ua":       ua,
		"host":     host,
		"duration": duration,
	}
}
