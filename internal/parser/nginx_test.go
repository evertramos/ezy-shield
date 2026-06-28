package parser_test

import (
	"bufio"
	"encoding/json"
	"net/netip"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// runNginxGoldenTest parses every line in fixtureFile and compares resulting
// events against the expected events in goldenFile.
func runNginxGoldenTest(t *testing.T, fixtureFile, goldenFile, origin string, cfg parser.NginxConfig) {
	t.Helper()

	p := parser.NewNginxParser(discardLogger(), cfg)

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

// TestNginxParser_GoldenCombined tests parsing of nginx "combined" format lines.
func TestNginxParser_GoldenCombined(t *testing.T) {
	runNginxGoldenTest(t,
		"../../fixtures/nginx/combined.log",
		"../../fixtures/nginx/combined.log.golden.json",
		"file:/var/log/nginx/access.log",
		parser.NginxConfig{},
	)
}

// TestNginxParser_GoldenScanner tests scanner traffic (wp-login, .env probes, etc.).
func TestNginxParser_GoldenScanner(t *testing.T) {
	runNginxGoldenTest(t,
		"../../fixtures/nginx/scanner.log",
		"../../fixtures/nginx/scanner.log.golden.json",
		"file:/var/log/nginx/access.log",
		parser.NginxConfig{},
	)
}

// TestNginxParser_GoldenIPv6 tests IPv6 client addresses including bots.
func TestNginxParser_GoldenIPv6(t *testing.T) {
	runNginxGoldenTest(t,
		"../../fixtures/nginx/ipv6.log",
		"../../fixtures/nginx/ipv6.log.golden.json",
		"file:/var/log/nginx/access.log",
		parser.NginxConfig{},
	)
}

// TestNginxParser_GoldenJSON tests auto-detected JSON log format.
func TestNginxParser_GoldenJSON(t *testing.T) {
	runNginxGoldenTest(t,
		"../../fixtures/nginx/json.log",
		"../../fixtures/nginx/json.log.golden.json",
		"journald:nginx",
		parser.NginxConfig{},
	)
}

// TestNginxParser_GoldenMalformed verifies that malformed lines are silently
// skipped while valid lines in the same file are still parsed.
func TestNginxParser_GoldenMalformed(t *testing.T) {
	runNginxGoldenTest(t,
		"../../fixtures/nginx/malformed.log",
		"../../fixtures/nginx/malformed.log.golden.json",
		"file:/var/log/nginx/access.log",
		parser.NginxConfig{},
	)
}

// TestNginxParser_Matches verifies the Matches predicate.
func TestNginxParser_Matches(t *testing.T) {
	p := parser.NewNginxParser(discardLogger(), parser.NginxConfig{})

	cases := []struct {
		source string
		want   bool
	}{
		{"journald:nginx", true},
		{"file:/var/log/nginx/access.log", true},
		{"file:/var/log/nginx/error.log", true},
		{"file:/etc/nginx/custom.log", true},
		{"nginx:proxy-web-auto", true},            // docker collector with parser: nginx
		{"nginx:/var/log/custom/proxy.log", true}, // file collector with parser: nginx
		{"apache:wordpress-app", true},            // docker collector with parser: apache (combined-log alias)
		{"apache:/var/log/apache2/access.log", true},
		{"apache-error:my-container", false}, // handled by ApacheErrorParser, not here
		{"file:/var/log/auth.log", false},
		{"journald:sshd", false},
		{"ssh:mycontainer", false},
		{"", false},
	}
	for _, tc := range cases {
		got := p.Matches(tc.source)
		if got != tc.want {
			t.Errorf("Matches(%q) = %v, want %v", tc.source, got, tc.want)
		}
	}
}

// TestNginxParser_GoldenVhostCombined tests parsing of nginx-proxy/jwilder
// vhost-prefixed combined format ($host $remote_addr - ...).
func TestNginxParser_GoldenVhostCombined(t *testing.T) {
	runNginxGoldenTest(t,
		"../../fixtures/nginx/vhost.log",
		"../../fixtures/nginx/vhost.log.golden.json",
		"nginx:proxy-web-auto",
		parser.NginxConfig{},
	)
}

// TestNginxParser_GoldenDockerJSON tests automatic unwrapping of Docker
// json-file log wrappers before parsing the inner nginx log line.
func TestNginxParser_GoldenDockerJSON(t *testing.T) {
	runNginxGoldenTest(t,
		"../../fixtures/nginx/docker_json.log",
		"../../fixtures/nginx/docker_json.log.golden.json",
		"nginx:proxy-web-auto",
		parser.NginxConfig{},
	)
}

// TestNginxParser_VhostCombinedEdgeCases covers edge cases for the vhost format.
func TestNginxParser_VhostCombinedEdgeCases(t *testing.T) {
	p := parser.NewNginxParser(discardLogger(), parser.NginxConfig{})

	cases := []struct {
		name      string
		line      string
		wantCount int
		wantIP    string
	}{
		{
			name:      "valid vhost combined IPv4",
			line:      `example.com 192.0.2.30 - - [15/Jan/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`,
			wantCount: 1,
			wantIP:    "192.0.2.30",
		},
		{
			name:      "valid vhost combined IPv6",
			line:      `example.com 2001:db8::5 - - [15/Jan/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 0 "-" "test"`,
			wantCount: 1,
			wantIP:    "2001:db8::5",
		},
		{
			name:      "invalid IP in second field",
			line:      `example.com not-an-ip - - [15/Jan/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 0 "-" "test"`,
			wantCount: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := p.Parse(sdk.RawLine{
				Source: "nginx:proxy-web",
				Line:   []byte(tc.line),
				At:     time.Now(),
			})
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			if len(evs) != tc.wantCount {
				t.Fatalf("event count: got %d, want %d", len(evs), tc.wantCount)
			}
			if tc.wantCount > 0 && tc.wantIP != "" {
				if evs[0].SourceIP.String() != tc.wantIP {
					t.Errorf("SourceIP: got %q, want %q", evs[0].SourceIP, tc.wantIP)
				}
			}
		})
	}
}

// TestNginxParser_DockerJSONUnwrap verifies that Docker json-file log lines are
// unwrapped before parsing, and that non-Docker JSON lines are handled correctly.
func TestNginxParser_DockerJSONUnwrap(t *testing.T) {
	p := parser.NewNginxParser(discardLogger(), parser.NginxConfig{})

	cases := []struct {
		name      string
		line      string
		wantCount int
		wantIP    string
	}{
		{
			name:      "docker json wrapper unwrapped",
			line:      `{"log":"192.0.2.50 - - [15/Jan/2025:10:00:01 +0000] \"GET / HTTP/1.1\" 200 1234 \"-\" \"curl\"\n","stream":"stdout","time":"2025-01-15T10:00:01Z"}`,
			wantCount: 1,
			wantIP:    "192.0.2.50",
		},
		{
			name:      "plain nginx JSON (not docker wrapper) still parsed",
			line:      `{"remote_addr":"192.0.2.51","request":"GET /api HTTP/1.1","status":"200","body_bytes_sent":"0","http_user_agent":"go-test"}`,
			wantCount: 1,
			wantIP:    "192.0.2.51",
		},
		{
			name:      "docker wrapper with nginx JSON inner content",
			line:      `{"log":"{\"remote_addr\":\"192.0.2.52\",\"request\":\"GET /json HTTP/1.1\",\"status\":\"200\",\"body_bytes_sent\":\"0\",\"http_user_agent\":\"ua\"}\n","stream":"stdout","time":"2025-01-15T10:00:01Z"}`,
			wantCount: 1,
			wantIP:    "192.0.2.52",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := p.Parse(sdk.RawLine{
				Source: "nginx:my-proxy",
				Line:   []byte(tc.line),
				At:     time.Now(),
			})
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			if len(evs) != tc.wantCount {
				t.Fatalf("event count: got %d, want %d (line: %s)", len(evs), tc.wantCount, tc.name)
			}
			if tc.wantCount > 0 && tc.wantIP != "" {
				if evs[0].SourceIP.String() != tc.wantIP {
					t.Errorf("SourceIP: got %q, want %q", evs[0].SourceIP, tc.wantIP)
				}
			}
		})
	}
}

// TestNginxParser_EdgeCases covers table-driven edge-case inputs.
func TestNginxParser_EdgeCases(t *testing.T) {
	p := parser.NewNginxParser(discardLogger(), parser.NginxConfig{})

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
			line:      []byte(makeLongLine(4097)),
			wantCount: 0,
		},
		{
			name:      "junk text",
			line:      []byte("THIS IS NOT A VALID LOG LINE"),
			wantCount: 0,
		},
		{
			name:      "valid combined IPv4",
			line:      []byte(`192.0.2.1 - - [01/Jan/2025:00:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`),
			wantCount: 1,
		},
		{
			name:      "valid combined IPv6",
			line:      []byte(`2001:db8::1 - - [01/Jan/2025:00:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`),
			wantCount: 1,
		},
		{
			name:      "combined bytes field is dash",
			line:      []byte(`192.0.2.1 - - [01/Jan/2025:00:00:01 +0000] "GET /redirect HTTP/1.1" 301 - "-" "Mozilla/5.0"`),
			wantCount: 1,
		},
		{
			name:      "invalid IP in combined",
			line:      []byte(`not-an-ip - - [01/Jan/2025:00:00:01 +0000] "GET / HTTP/1.1" 200 0 "-" "test"`),
			wantCount: 0,
		},
		{
			name:      "valid JSON line",
			line:      []byte(`{"remote_addr":"192.0.2.2","request":"GET /json HTTP/1.1","status":"200","body_bytes_sent":"42","http_user_agent":"curl/7.68.0","http_x_forwarded_for":"-"}`),
			wantCount: 1,
		},
		{
			name:      "JSON missing remote_addr",
			line:      []byte(`{"request":"GET / HTTP/1.1","status":"200"}`),
			wantCount: 0,
		},
		{
			name:      "malformed JSON",
			line:      []byte(`{not valid json`),
			wantCount: 0,
		},
		{
			// ANSI escapes in UA are parsed but the field is capped at maxUABytes.
			name:      "ANSI escape in UA",
			line:      []byte("192.0.2.1 - - [01/Jan/2025:00:00:01 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"\x1b[31mEvil\x1b[0m\""),
			wantCount: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := p.Parse(sdk.RawLine{
				Source: "file:/var/log/nginx/access.log",
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

// TestNginxParser_XFF verifies that X-Forwarded-For is used only when the
// connecting address is a configured trusted proxy (anti-spoofing).
func TestNginxParser_XFF(t *testing.T) {
	trustedPrefix := netip.MustParsePrefix("10.0.0.0/8")
	cfg := parser.NginxConfig{TrustedProxies: []netip.Prefix{trustedPrefix}}
	p := parser.NewNginxParser(discardLogger(), cfg)

	t.Run("trusted proxy: XFF used", func(t *testing.T) {
		// remote_addr is 10.0.0.1 (trusted); real client is 203.0.113.99 via XFF.
		line := sdk.RawLine{
			Source: "journald:nginx",
			Line:   []byte(`{"remote_addr":"10.0.0.1","request":"GET / HTTP/1.1","status":"200","body_bytes_sent":"0","http_user_agent":"test","http_x_forwarded_for":"203.0.113.99"}`),
			At:     time.Now(),
		}
		evs, err := p.Parse(line)
		if err != nil || len(evs) != 1 {
			t.Fatalf("expected 1 event, got %d (err=%v)", len(evs), err)
		}
		if evs[0].SourceIP.String() != "203.0.113.99" {
			t.Errorf("SourceIP: got %q, want 203.0.113.99", evs[0].SourceIP)
		}
	})

	t.Run("untrusted remote: XFF ignored", func(t *testing.T) {
		// remote_addr is NOT in trusted proxies; XFF header must be ignored.
		line := sdk.RawLine{
			Source: "journald:nginx",
			Line:   []byte(`{"remote_addr":"198.51.100.5","request":"GET / HTTP/1.1","status":"200","body_bytes_sent":"0","http_user_agent":"attacker","http_x_forwarded_for":"1.2.3.4"}`),
			At:     time.Now(),
		}
		evs, err := p.Parse(line)
		if err != nil || len(evs) != 1 {
			t.Fatalf("expected 1 event, got %d (err=%v)", len(evs), err)
		}
		if evs[0].SourceIP.String() != "198.51.100.5" {
			t.Errorf("SourceIP: got %q, want 198.51.100.5 (XFF must not be trusted)", evs[0].SourceIP)
		}
	})

	t.Run("no trusted_proxies configured: XFF always ignored", func(t *testing.T) {
		pNoTrust := parser.NewNginxParser(discardLogger(), parser.NginxConfig{})
		line := sdk.RawLine{
			Source: "journald:nginx",
			Line:   []byte(`{"remote_addr":"10.0.0.1","request":"GET / HTTP/1.1","status":"200","body_bytes_sent":"0","http_user_agent":"test","http_x_forwarded_for":"1.2.3.4"}`),
			At:     time.Now(),
		}
		evs, err := pNoTrust.Parse(line)
		if err != nil || len(evs) != 1 {
			t.Fatalf("expected 1 event, got %d (err=%v)", len(evs), err)
		}
		if evs[0].SourceIP.String() != "10.0.0.1" {
			t.Errorf("SourceIP: got %q, want 10.0.0.1 (XFF must not be used without trusted_proxies)", evs[0].SourceIP)
		}
	})
}

// TestNginxParser_CustomFormat verifies that a user-supplied regex with named
// capture groups is tried when neither combined nor JSON formats match.
func TestNginxParser_CustomFormat(t *testing.T) {
	// "common" format: no referer, no UA.
	customRE := regexp.MustCompile(
		`^(?P<remote_addr>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]{1,16})\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{1,3})\s+(?P<bytes>\d+|-)`,
	)
	cfg := parser.NginxConfig{CustomFormats: []*regexp.Regexp{customRE}}
	p := parser.NewNginxParser(discardLogger(), cfg)

	line := sdk.RawLine{
		Source: "file:/var/log/nginx/access.log",
		Line:   []byte(`192.0.2.10 - bob [15/Jan/2025:10:00:01 +0000] "GET /custom HTTP/1.1" 200 512`),
		At:     time.Now(),
	}
	evs, err := p.Parse(line)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Kind != "http_request" {
		t.Errorf("kind: got %q, want %q", ev.Kind, "http_request")
	}
	if ev.SourceIP.String() != "192.0.2.10" {
		t.Errorf("source_ip: got %q, want 192.0.2.10", ev.SourceIP)
	}
	if ev.Fields["path"] != "/custom" {
		t.Errorf("path: got %q, want /custom", ev.Fields["path"])
	}
	if ev.Fields["status"] != "200" {
		t.Errorf("status: got %q, want 200", ev.Fields["status"])
	}
}

// TestNginxParser_UACap verifies that the UA field is truncated at 512 bytes.
func TestNginxParser_UACap(t *testing.T) {
	p := parser.NewNginxParser(discardLogger(), parser.NginxConfig{})

	longUA := makeLongLine(600)
	rawLine := []byte(`192.0.2.1 - - [01/Jan/2025:00:00:01 +0000] "GET /path HTTP/1.1" 200 0 "-" "` + longUA + `"`)
	if len(rawLine) > 4096 {
		t.Skip("constructed line exceeds line cap; adjust test")
	}

	evs, err := p.Parse(sdk.RawLine{
		Source: "file:/var/log/nginx/access.log",
		Line:   rawLine,
		At:     time.Now(),
	})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if len(evs[0].Fields["ua"]) > 512 {
		t.Errorf("ua field exceeds 512 bytes: %d", len(evs[0].Fields["ua"]))
	}
}

// makeLongLine returns a string of n 'A' bytes for oversized-line edge-case tests.
func makeLongLine(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'A'
	}
	return string(b)
}
