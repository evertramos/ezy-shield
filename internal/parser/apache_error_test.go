package parser_test

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// runApacheErrorGoldenTest parses every line in fixtureFile and compares the
// resulting events against the expected events in goldenFile.
func runApacheErrorGoldenTest(t *testing.T, fixtureFile, goldenFile, origin string) {
	t.Helper()

	p := parser.NewApacheErrorParser(discardLogger())

	f, err := os.Open(fixtureFile) //nolint:gosec // fixtureFile is a test-controlled constant path, not attacker-controlled
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close() //nolint:errcheck

	var got []sdk.Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		evs, parseErr := p.Parse(sdk.RawLine{
			Source: origin,
			Line:   []byte(line),
			At:     time.Now(),
		})
		if parseErr != nil {
			t.Errorf("Parse(%q) returned error: %v", line, parseErr)
			continue
		}
		got = append(got, evs...)
	}
	if scanErr := sc.Err(); scanErr != nil {
		t.Fatalf("scan fixture: %v", scanErr)
	}

	gf, err := os.ReadFile(goldenFile) //nolint:gosec // goldenFile is a test-controlled constant path, not attacker-controlled
	if err != nil {
		t.Fatalf("open golden: %v", err)
	}
	var want []goldenEvent
	if err := json.Unmarshal(gf, &want); err != nil {
		t.Fatalf("parse golden JSON: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("event count mismatch: got %d, want %d", len(got), len(want))
	}

	for i, w := range want {
		g := got[i]
		if g.Kind != w.Kind {
			t.Errorf("event[%d] kind: got %q, want %q", i, g.Kind, w.Kind)
		}
		if g.SourceIP.String() != w.SourceIP {
			t.Errorf("event[%d] source_ip: got %q, want %q", i, g.SourceIP.String(), w.SourceIP)
		}
		for k, wv := range w.Fields {
			gv := g.Fields[k]
			if gv != wv {
				t.Errorf("event[%d] field %q: got %q, want %q", i, k, gv, wv)
			}
		}
	}
}

// TestApacheErrorParser_Golden walks the fixture covering Apache 2.4
// module:level form, 2.2 single-level form, AHnnnnn code extraction, IPv4 with
// and without port, bracketed IPv6 with port, modules without leading codes,
// pid/tid headers, and a junk line that must be skipped.
func TestApacheErrorParser_Golden(t *testing.T) {
	runApacheErrorGoldenTest(t,
		"../../fixtures/apache/error.log",
		"../../fixtures/apache/error.log.golden.json",
		"file:/var/log/apache2/error.log",
	)
}

// TestApacheErrorParser_Matches verifies the Matches predicate.
func TestApacheErrorParser_Matches(t *testing.T) {
	p := parser.NewApacheErrorParser(discardLogger())

	cases := []struct {
		source string
		want   bool
	}{
		{"apache-error:my-container", true},
		{"apache-error:/custom/path", true},
		{"file:/var/log/apache2/error.log", true},
		{"file:/var/log/httpd/error_log", true},
		{"file:/var/log/apache2/access.log", false},
		{"file:/var/log/nginx/access.log", false},
		{"apache:my-container", false}, // combined-log alias is handled by NginxParser
		{"journald:sshd", false},
		{"", false},
	}
	for _, tc := range cases {
		got := p.Matches(tc.source)
		if got != tc.want {
			t.Errorf("Matches(%q) = %v, want %v", tc.source, got, tc.want)
		}
	}
}

// TestApacheErrorParser_EdgeCases covers table-driven inputs that exercise the
// parser's parsing/skip boundaries.
func TestApacheErrorParser_EdgeCases(t *testing.T) {
	p := parser.NewApacheErrorParser(discardLogger())

	cases := []struct {
		name      string
		line      []byte
		wantCount int
	}{
		{
			name:      "empty line",
			line:      []byte(""),
			wantCount: 0,
		},
		{
			name:      "whitespace only",
			line:      []byte("   \t  "),
			wantCount: 0,
		},
		{
			name:      "oversized line",
			line:      []byte(strings.Repeat("A", 4097)),
			wantCount: 0,
		},
		{
			name:      "junk text",
			line:      []byte("THIS IS NOT A VALID APACHE LINE"),
			wantCount: 0,
		},
		{
			name:      "no client field (server message)",
			line:      []byte("[Fri Jun 26 19:00:03.000000 2026] [mpm_event:notice] [pid 999] AH00489: Apache configured"),
			wantCount: 0,
		},
		{
			name:      "apache 2.4 ipv4 with port",
			line:      []byte("[Fri Jun 26 19:00:00.123456 2026] [core:error] [pid 1234] [client 203.0.113.1:5678] AH00124: msg"),
			wantCount: 1,
		},
		{
			name:      "apache 2.4 ipv4 no port",
			line:      []byte("[Fri Jun 26 19:00:00.123456 2026] [core:error] [pid 1234] [client 203.0.113.1] msg"),
			wantCount: 1,
		},
		{
			name:      "apache 2.4 ipv6 in brackets with port",
			line:      []byte("[Fri Jun 26 19:00:00.123456 2026] [core:error] [pid 1234] [client [2001:db8::1]:5678] msg"),
			wantCount: 1,
		},
		{
			name:      "apache 2.2 legacy without pid and module",
			line:      []byte("[Fri Jun 26 19:00:06 2026] [error] [client 203.0.113.99] File does not exist"),
			wantCount: 1,
		},
		{
			name:      "invalid client IP",
			line:      []byte("[Fri Jun 26 19:00:00.123456 2026] [core:error] [pid 1234] [client not-an-ip] msg"),
			wantCount: 0,
		},
		{
			name:      "pid with tid",
			line:      []byte("[Fri Jun 26 19:00:00.123456 2026] [proxy_fcgi:error] [pid 1235:tid 1236] [client 198.51.100.10:44321] AH01071: m"),
			wantCount: 1,
		},
		{
			name:      "ANSI escape in message",
			line:      []byte("[Fri Jun 26 19:00:00.123456 2026] [core:error] [pid 1234] [client 203.0.113.1:5678] \x1b[31mhostile\x1b[0m"),
			wantCount: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := p.Parse(sdk.RawLine{
				Source: "file:/var/log/apache2/error.log",
				Line:   tc.line,
				At:     time.Now(),
			})
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}
			if len(evs) != tc.wantCount {
				t.Errorf("event count: got %d, want %d", len(evs), tc.wantCount)
			}
		})
	}
}

// TestApacheErrorParser_MessageCap verifies the message field is truncated at
// maxApacheMsgBytes; an attacker controls path/UA fragments that frequently
// land in error messages, and we mirror the nginx UA cap to prevent storage
// inflation.
func TestApacheErrorParser_MessageCap(t *testing.T) {
	p := parser.NewApacheErrorParser(discardLogger())

	longMsg := strings.Repeat("A", 800)
	rawLine := []byte("[Fri Jun 26 19:00:00.123456 2026] [core:error] [pid 1234] [client 192.0.2.1:5678] " + longMsg)
	if len(rawLine) > 4096 {
		t.Skip("constructed line exceeds line cap; adjust test")
	}

	evs, err := p.Parse(sdk.RawLine{
		Source: "file:/var/log/apache2/error.log",
		Line:   rawLine,
		At:     time.Now(),
	})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if got := len(evs[0].Fields["msg"]); got > 512 {
		t.Errorf("msg field exceeds 512 bytes: %d", got)
	}
}

// TestNginxParser_ApacheAlias verifies that a collector configured with
// parser: apache routes through the NginxParser (Apache combined ≡ nginx
// combined) and produces http_request events. This is the Phase 1 alias from
// issue #94 — existing rules like wp-login/.env/xmlrpc must trigger unchanged.
func TestNginxParser_ApacheAlias(t *testing.T) {
	runNginxGoldenTest(t,
		"../../fixtures/apache/combined.log",
		"../../fixtures/apache/combined.log.golden.json",
		"apache:wordpress-app",
		parser.NginxConfig{},
	)
}
