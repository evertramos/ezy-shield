package parser

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// TraefikParser-specific field length caps.
const (
	maxRouterBytes  = 128
	maxServiceBytes = 256
)

// reTraefikCLF matches Traefik's Common Log Format with the default extras:
//
//	<ip> - <user> [<time>] "<method> <path> <proto>" <status> <bytes>
//	"<referer>" "<ua>" <req_count> "<router>" "<service>" <duration>
//
// Capture groups: 1=ip 2=method 3=path 4=status 5=bytes 6=ua 7=router 8=service 9=duration
var reTraefikCLF = regexp.MustCompile(
	`^(\S+)\s+-\s+\S+\s+\[[^\]]+\]\s+"([A-Z]{1,16})\s+(\S+)\s+\S+"\s+(\d{1,3})\s+(\d+|-)\s+"[^"]*"\s+"([^"]*)"\s+\d+\s+"([^"]*)"\s+"([^"]*)"\s+(\S+)`,
)

// TraefikConfig holds optional configuration for TraefikParser.
type TraefikConfig struct {
	// TrustedProxies lists CIDR ranges whose connecting IP may be overridden
	// by the X-Forwarded-For header. Empty means XFF is never trusted.
	TrustedProxies []netip.Prefix
}

// TraefikParser parses Traefik access log lines in CLF (with router/service/
// duration extras) or JSON format. It implements sdk.Parser.
//
// Sources handled: "journald:traefik", any source path containing "/traefik/",
// any source prefixed with "traefik:".
type TraefikParser struct {
	logger         *slog.Logger
	trustedProxies []netip.Prefix
}

// NewTraefikParser creates a TraefikParser that writes debug messages to logger.
func NewTraefikParser(logger *slog.Logger, cfg TraefikConfig) *TraefikParser {
	return &TraefikParser{
		logger:         logger,
		trustedProxies: cfg.TrustedProxies,
	}
}

// Matches reports whether this parser handles the given collector source ID.
func (p *TraefikParser) Matches(source string) bool {
	return source == "journald:traefik" ||
		strings.Contains(source, "/traefik/") ||
		strings.HasPrefix(source, "traefik:")
}

// Parse converts a single raw log line into zero or more http_request Events.
// Lines that are oversized, empty, or unrecognised are silently skipped (debug-logged).
// Malformed lines never panic or return a non-nil error.
func (p *TraefikParser) Parse(line sdk.RawLine) ([]sdk.Event, error) {
	if len(line.Line) > maxLineBytes {
		p.logger.Debug("traefik: line exceeds max size, skipping",
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
		ev, ok = p.parseCLF(raw, line.At, line.Source)
	}

	if !ok {
		p.logger.Debug("traefik: unrecognised line, skipping",
			slog.String("line", redactForLog(raw)),
		)
		return nil, nil
	}

	return []sdk.Event{ev}, nil
}

// parseCLF handles Traefik's CLF format with router/service/duration extras.
func (p *TraefikParser) parseCLF(raw string, at time.Time, origin string) (sdk.Event, bool) {
	m := reTraefikCLF.FindStringSubmatch(raw)
	if m == nil {
		return sdk.Event{}, false
	}
	ip, err := parseIP(m[1])
	if err != nil {
		p.logger.Debug("traefik: invalid IP in CLF line",
			slog.String("raw", redactForLog(m[1])),
		)
		return sdk.Event{}, false
	}
	return sdk.Event{
		Time:     at,
		SourceIP: ip,
		Kind:     "http_request",
		Fields:   traefikFields(m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9]),
		Origin:   origin,
	}, true
}

// parseJSON handles Traefik's JSON access log format. ClientHost is preferred;
// otherwise the host is extracted from ClientAddr ("IP:port" or "[IPv6]:port").
func (p *TraefikParser) parseJSON(raw string, at time.Time, origin string) (sdk.Event, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return sdk.Event{}, false
	}

	host := jsonString(obj, "ClientHost")
	if host == "" {
		addr := jsonString(obj, "ClientAddr")
		if addr == "" {
			return sdk.Event{}, false
		}
		if h, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			host = h
		} else {
			host = addr
		}
	}

	ip, err := parseIP(host)
	if err != nil {
		p.logger.Debug("traefik: invalid client address in JSON line",
			slog.String("raw", redactForLog(host)),
		)
		return sdk.Event{}, false
	}

	xff := jsonString(obj, "request_X-Forwarded-For", "RequestXForwardedFor")
	ip = p.resolveXFF(ip, xff)

	method := jsonString(obj, "RequestMethod")
	path := jsonString(obj, "RequestPath")
	status := jsonString(obj, "DownstreamStatus")
	bytesSent := jsonString(obj, "DownstreamContentSize")
	ua := jsonString(obj, "request_User-Agent", "RequestUserAgent")
	router := jsonString(obj, "RouterName")
	service := jsonString(obj, "ServiceName", "ServiceURL")
	duration := jsonString(obj, "Duration")

	return sdk.Event{
		Time:     at,
		SourceIP: ip,
		Kind:     "http_request",
		Fields:   traefikFields(method, path, status, bytesSent, ua, router, service, duration),
		Origin:   origin,
	}, true
}

// resolveXFF returns the effective client IP. If ip is a trusted proxy and xff
// contains a routable non-trusted address, that address is returned instead.
// Falls back to ip on any resolution failure.
func (p *TraefikParser) resolveXFF(ip netip.Addr, xff string) netip.Addr {
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
	p.logger.Debug("traefik: no untrusted IP in XFF, using client addr",
		slog.String("xff", redactForLog(xff)),
	)
	return ip
}

// isTrustedProxy reports whether ip falls within any configured trusted prefix.
func (p *TraefikParser) isTrustedProxy(ip netip.Addr) bool {
	for _, prefix := range p.trustedProxies {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// traefikFields constructs the Event.Fields map, capping each value at its maximum length.
func traefikFields(method, path, status, bytesSent, ua, router, service, duration string) map[string]string {
	if len(method) > maxMethodBytes {
		method = method[:maxMethodBytes]
	}
	if len(path) > maxPathBytes {
		path = path[:maxPathBytes]
	}
	if len(ua) > maxUABytes {
		ua = ua[:maxUABytes]
	}
	if len(router) > maxRouterBytes {
		router = router[:maxRouterBytes]
	}
	if len(service) > maxServiceBytes {
		service = service[:maxServiceBytes]
	}
	return map[string]string{
		"method":   method,
		"path":     path,
		"status":   status,
		"bytes":    bytesSent,
		"ua":       ua,
		"router":   router,
		"service":  service,
		"duration": duration,
	}
}
