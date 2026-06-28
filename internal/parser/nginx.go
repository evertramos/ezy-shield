package parser

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// NginxParser-specific field length caps.
const (
	maxPathBytes   = 2048
	maxUABytes     = 512
	maxMethodBytes = 16
)

// reNginxCombined matches the default nginx "combined" log format:
//
//	$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
var reNginxCombined = regexp.MustCompile(
	`^(\S+)\s+-\s+\S+\s+\[[^\]]+\]\s+"([A-Z]{1,16})\s+(\S+)\s+\S+"\s+(\d{1,3})\s+(\d+|-)\s+"[^"]*"\s+"([^"]*)"`,
)

// reNginxVhostCombined matches the nginx-proxy/jwilder vhost-prefixed combined format:
//
//	$host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
var reNginxVhostCombined = regexp.MustCompile(
	`^\S+\s+(\S+)\s+-\s+\S+\s+\[[^\]]+\]\s+"([A-Z]{1,16})\s+(\S+)\s+\S+"\s+(\d{1,3})\s+(\d+|-)\s+"[^"]*"\s+"([^"]*)"`,
)

// NginxConfig holds optional configuration for NginxParser.
//
// # Adding a custom log format
//
// Compile a *regexp.Regexp with named capture groups and append it to CustomFormats.
// Required groups: remote_addr, method, path, status, bytes.
// Optional groups: ua (User-Agent), xff (X-Forwarded-For value).
//
// Example (nginx "common" format without referer/UA):
//
//	pat := regexp.MustCompile(
//	    `^(?P<remote_addr>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]{1,16})\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{1,3})\s+(?P<bytes>\d+|-)`)
//	cfg := parser.NginxConfig{CustomFormats: []*regexp.Regexp{pat}}
type NginxConfig struct {
	// TrustedProxies lists CIDR ranges whose connecting IP may be overridden
	// by the X-Forwarded-For header. Empty means XFF is never trusted.
	TrustedProxies []netip.Prefix
	// CustomFormats are additional log-format regexes tried after "combined"
	// fails. See the NginxConfig doc for required named capture groups.
	CustomFormats []*regexp.Regexp
}

// NginxParser parses nginx access log lines in "combined" format, JSON format,
// or user-supplied custom formats (see NginxConfig). It implements sdk.Parser.
//
// Sources handled: "journald:nginx", any source path containing "/nginx/",
// any source prefixed with "nginx:" or "apache:" (Apache shares the combined
// access log format).
type NginxParser struct {
	logger         *slog.Logger
	trustedProxies []netip.Prefix
	customFormats  []*regexp.Regexp
}

// NewNginxParser creates a NginxParser that writes debug messages to logger.
func NewNginxParser(logger *slog.Logger, cfg NginxConfig) *NginxParser {
	return &NginxParser{
		logger:         logger,
		trustedProxies: cfg.TrustedProxies,
		customFormats:  cfg.CustomFormats,
	}
}

// Matches reports whether this parser handles the given collector source ID.
// Apache uses the same "combined" access log format as nginx, so collectors
// with parser: apache (source prefix "apache:") are handled here as well.
func (p *NginxParser) Matches(source string) bool {
	return source == "journald:nginx" ||
		strings.Contains(source, "/nginx/") ||
		strings.HasPrefix(source, "nginx:") ||
		strings.HasPrefix(source, "apache:")
}

// Parse converts a single raw log line into zero or more http_request Events.
// Lines that are oversized, empty, or unrecognised are silently skipped (debug-logged).
// Malformed lines never panic or return a non-nil error.
func (p *NginxParser) Parse(line sdk.RawLine) ([]sdk.Event, error) {
	if len(line.Line) > maxLineBytes {
		p.logger.Debug("nginx: line exceeds max size, skipping",
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

	if raw[0] == '{' {
		ev, ok = p.parseJSON(raw, line.At, line.Source)
	} else {
		ev, ok = p.parseCombined(raw, line.At, line.Source)
		if !ok {
			ev, ok = p.parseVhostCombined(raw, line.At, line.Source)
		}
		if !ok {
			ev, ok = p.parseCustom(raw, line.At, line.Source)
		}
	}

	if !ok {
		p.logger.Debug("nginx: unrecognised line, skipping",
			slog.String("line", redactForLog(raw)),
		)
		return nil, nil
	}

	return []sdk.Event{ev}, nil
}

// parseCombined handles the default nginx "combined" log format.
func (p *NginxParser) parseCombined(raw string, at time.Time, origin string) (sdk.Event, bool) {
	m := reNginxCombined.FindStringSubmatch(raw)
	if m == nil {
		return sdk.Event{}, false
	}
	// m[1]=remote_addr m[2]=method m[3]=path m[4]=status m[5]=bytes m[6]=ua
	ip, err := parseIP(m[1])
	if err != nil {
		p.logger.Debug("nginx: invalid IP in combined line",
			slog.String("raw", redactForLog(m[1])),
		)
		return sdk.Event{}, false
	}
	return sdk.Event{
		Time:     at,
		SourceIP: ip,
		Kind:     "http_request",
		Fields:   nginxFields(m[2], m[3], m[4], m[5], m[6]),
		Origin:   origin,
	}, true
}

// parseJSON handles nginx access logs written in JSON format.
// It supports both string and numeric values for status/bytes fields.
func (p *NginxParser) parseJSON(raw string, at time.Time, origin string) (sdk.Event, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return sdk.Event{}, false
	}

	remoteAddr := jsonString(obj, "remote_addr", "client")
	if remoteAddr == "" {
		return sdk.Event{}, false
	}

	ip, err := parseIP(remoteAddr)
	if err != nil {
		p.logger.Debug("nginx: invalid remote_addr in JSON line",
			slog.String("raw", redactForLog(remoteAddr)),
		)
		return sdk.Event{}, false
	}

	xff := jsonString(obj, "http_x_forwarded_for", "x_forwarded_for")
	ip = p.resolveXFF(ip, xff)

	request := jsonString(obj, "request")
	method, path := splitHTTPRequest(request)

	status := jsonString(obj, "status")
	bytesSent := jsonString(obj, "body_bytes_sent", "bytes_sent")
	ua := jsonString(obj, "http_user_agent", "user_agent", "agent")

	return sdk.Event{
		Time:     at,
		SourceIP: ip,
		Kind:     "http_request",
		Fields:   nginxFields(method, path, status, bytesSent, ua),
		Origin:   origin,
	}, true
}

// parseVhostCombined handles the nginx-proxy/jwilder vhost-prefixed combined format:
//
//	$host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
func (p *NginxParser) parseVhostCombined(raw string, at time.Time, origin string) (sdk.Event, bool) {
	m := reNginxVhostCombined.FindStringSubmatch(raw)
	if m == nil {
		return sdk.Event{}, false
	}
	// m[1]=remote_addr m[2]=method m[3]=path m[4]=status m[5]=bytes m[6]=ua
	ip, err := parseIP(m[1])
	if err != nil {
		p.logger.Debug("nginx: invalid IP in vhost combined line",
			slog.String("raw", redactForLog(m[1])),
		)
		return sdk.Event{}, false
	}
	return sdk.Event{
		Time:     at,
		SourceIP: ip,
		Kind:     "http_request",
		Fields:   nginxFields(m[2], m[3], m[4], m[5], m[6]),
		Origin:   origin,
	}, true
}

// extractDockerLogField returns the value of the "log" key if raw is a Docker
// json-file log entry ({"log":"...","stream":"..."}). Returns "" otherwise.
// This is a separate function (not parseJSON) because Docker's "log" value is
// the raw log line, not nginx JSON output.
func extractDockerLogField(raw string) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return ""
	}
	logVal, ok := obj["log"]
	if !ok {
		return ""
	}
	// Require "stream" key to distinguish Docker JSON from nginx JSON log format.
	if _, hasStream := obj["stream"]; !hasStream {
		return ""
	}
	var s string
	if err := json.Unmarshal(logVal, &s); err != nil {
		return ""
	}
	return s
}

// parseCustom tries each configured custom-format regex in order.
func (p *NginxParser) parseCustom(raw string, at time.Time, origin string) (sdk.Event, bool) {
	for _, re := range p.customFormats {
		m := re.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		named := namedGroups(re, m)

		remoteAddr := named["remote_addr"]
		if remoteAddr == "" {
			continue
		}
		ip, err := parseIP(remoteAddr)
		if err != nil {
			p.logger.Debug("nginx: invalid IP in custom line",
				slog.String("raw", redactForLog(remoteAddr)),
			)
			continue
		}

		ip = p.resolveXFF(ip, named["xff"])

		return sdk.Event{
			Time:     at,
			SourceIP: ip,
			Kind:     "http_request",
			Fields:   nginxFields(named["method"], named["path"], named["status"], named["bytes"], named["ua"]),
			Origin:   origin,
		}, true
	}
	return sdk.Event{}, false
}

// resolveXFF returns the effective client IP. If ip is a trusted proxy and xff
// contains a routable non-trusted address, that address is returned instead.
// Falls back to ip on any resolution failure.
func (p *NginxParser) resolveXFF(ip netip.Addr, xff string) netip.Addr {
	if xff == "" || xff == "-" || len(p.trustedProxies) == 0 {
		return ip
	}
	if !p.isTrustedProxy(ip) {
		return ip
	}
	effective, err := p.firstUntrustedFromXFF(xff)
	if err != nil {
		p.logger.Debug("nginx: XFF resolution failed, using remote_addr",
			slog.String("err", err.Error()),
		)
		return ip
	}
	return effective
}

// isTrustedProxy reports whether ip falls within any configured trusted prefix.
func (p *NginxParser) isTrustedProxy(ip netip.Addr) bool {
	for _, prefix := range p.trustedProxies {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// firstUntrustedFromXFF extracts the leftmost non-trusted IP from an
// X-Forwarded-For header value (format: "client, proxy1, proxy2").
func (p *NginxParser) firstUntrustedFromXFF(xff string) (netip.Addr, error) {
	for _, part := range strings.Split(xff, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "-" {
			continue
		}
		ip, err := parseIP(part)
		if err != nil {
			continue
		}
		if !p.isTrustedProxy(ip) {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("nginx: no untrusted IP in XFF %q", redactForLog(xff))
}

// nginxFields constructs the Event.Fields map, capping each value at its maximum length.
func nginxFields(method, path, status, bytesSent, ua string) map[string]string {
	if len(method) > maxMethodBytes {
		method = method[:maxMethodBytes]
	}
	if len(path) > maxPathBytes {
		path = path[:maxPathBytes]
	}
	if len(ua) > maxUABytes {
		ua = ua[:maxUABytes]
	}
	return map[string]string{
		"method": method,
		"path":   path,
		"status": status,
		"bytes":  bytesSent,
		"ua":     ua,
	}
}

// splitHTTPRequest splits "METHOD URI HTTP/x.x" into (method, path).
// Returns ("", "") for empty or unparseable requests.
func splitHTTPRequest(req string) (method, path string) {
	if req == "" || req == "-" {
		return "", ""
	}
	parts := strings.SplitN(req, " ", 3)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// jsonString returns the first non-empty string found under any of keys in obj.
// Bare JSON numbers are converted to their decimal string representation.
func jsonString(obj map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		v, ok := obj[k]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			return s
		}
		var n json.Number
		if err := json.Unmarshal(v, &n); err == nil {
			return n.String()
		}
	}
	return ""
}

// namedGroups maps subexpression names to their captured values for a match.
func namedGroups(re *regexp.Regexp, m []string) map[string]string {
	names := re.SubexpNames()
	out := make(map[string]string, len(names))
	for i, n := range names {
		if n != "" && i < len(m) {
			out[n] = m[i]
		}
	}
	return out
}
