package parser_test

import (
	"bufio"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// runTraefikGoldenTest parses every line in fixtureFile and compares resulting
// events against the expected events in goldenFile.
func runTraefikGoldenTest(t *testing.T, fixtureFile, goldenFile, origin string, cfg parser.TraefikConfig) {
	t.Helper()

	p := parser.NewTraefikParser(discardLogger(), cfg)

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

// TestTraefikParser_GoldenCLF tests parsing of Traefik CLF format with extras.
func TestTraefikParser_GoldenCLF(t *testing.T) {
	runTraefikGoldenTest(t,
		"../../fixtures/traefik/clf.log",
		"../../fixtures/traefik/clf.log.golden.json",
		"file:/var/log/traefik/access.log",
		parser.TraefikConfig{},
	)
}

// TestTraefikParser_GoldenJSON tests parsing of Traefik JSON access log format.
func TestTraefikParser_GoldenJSON(t *testing.T) {
	runTraefikGoldenTest(t,
		"../../fixtures/traefik/json.log",
		"../../fixtures/traefik/json.log.golden.json",
		"traefik:traefik",
		parser.TraefikConfig{},
	)
}

// TestTraefikParser_GoldenDockerJSON tests automatic unwrapping of Docker
// json-file log wrappers around Traefik CLF and JSON lines.
func TestTraefikParser_GoldenDockerJSON(t *testing.T) {
	runTraefikGoldenTest(t,
		"../../fixtures/traefik/docker_json.log",
		"../../fixtures/traefik/docker_json.log.golden.json",
		"traefik:traefik",
		parser.TraefikConfig{},
	)
}

// TestTraefikParser_Matches verifies the Matches predicate.
func TestTraefikParser_Matches(t *testing.T) {
	p := parser.NewTraefikParser(discardLogger(), parser.TraefikConfig{})

	cases := []struct {
		source string
		want   bool
	}{
		{"journald:traefik", true},
		{"file:/var/log/traefik/access.log", true},
		{"traefik:traefik", true},
		{"traefik:proxy-edge", true},
		{"traefik:/var/log/custom/proxy.log", true},
		{"journald:nginx", false},
		{"file:/var/log/auth.log", false},
		{"nginx:proxy-web", false},
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

// TestTraefikParser_ClientAddrIPv6 verifies that the JSON ClientAddr field has
// its port stripped, including the bracketed IPv6 form Traefik emits.
func TestTraefikParser_ClientAddrIPv6(t *testing.T) {
	p := parser.NewTraefikParser(discardLogger(), parser.TraefikConfig{})

	cases := []struct {
		name   string
		line   string
		wantIP string
	}{
		{
			name:   "IPv4 with port",
			line:   `{"ClientAddr":"192.0.2.10:5678","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200,"DownstreamContentSize":0,"RouterName":"r","ServiceName":"s","Duration":1}`,
			wantIP: "192.0.2.10",
		},
		{
			name:   "IPv6 bracketed with port",
			line:   `{"ClientAddr":"[2001:db8::5]:5678","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200,"DownstreamContentSize":0,"RouterName":"r","ServiceName":"s","Duration":1}`,
			wantIP: "2001:db8::5",
		},
		{
			name:   "ClientHost preferred over ClientAddr",
			line:   `{"ClientAddr":"192.0.2.99:5678","ClientHost":"192.0.2.42","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200,"DownstreamContentSize":0,"RouterName":"r","ServiceName":"s","Duration":1}`,
			wantIP: "192.0.2.42",
		},
		{
			name:   "ClientAddr without port",
			line:   `{"ClientAddr":"192.0.2.55","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200,"DownstreamContentSize":0,"RouterName":"r","ServiceName":"s","Duration":1}`,
			wantIP: "192.0.2.55",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := p.Parse(sdk.RawLine{
				Source: "traefik:traefik",
				Line:   []byte(tc.line),
				At:     time.Now(),
			})
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			if len(evs) != 1 {
				t.Fatalf("expected 1 event, got %d", len(evs))
			}
			if evs[0].SourceIP.String() != tc.wantIP {
				t.Errorf("SourceIP: got %q, want %q", evs[0].SourceIP, tc.wantIP)
			}
		})
	}
}

// TestTraefikParser_EdgeCases covers table-driven edge-case inputs.
func TestTraefikParser_EdgeCases(t *testing.T) {
	p := parser.NewTraefikParser(discardLogger(), parser.TraefikConfig{})

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
			name:      "valid CLF IPv4",
			line:      []byte(`192.0.2.1 - - [26/Jun/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 0 "-" "test" 1 "r@docker" "http://b:80" 2ms`),
			wantCount: 1,
		},
		{
			name:      "valid CLF IPv6",
			line:      []byte(`2001:db8::1 - - [26/Jun/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 0 "-" "test" 1 "r@docker" "http://b:80" 2ms`),
			wantCount: 1,
		},
		{
			name:      "CLF missing extras (nginx-like, must NOT match Traefik)",
			line:      []byte(`192.0.2.1 - - [26/Jun/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 0 "-" "test"`),
			wantCount: 0,
		},
		{
			name:      "invalid IP in CLF",
			line:      []byte(`not-an-ip - - [26/Jun/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 0 "-" "test" 1 "r@docker" "http://b:80" 2ms`),
			wantCount: 0,
		},
		{
			name:      "valid JSON line",
			line:      []byte(`{"ClientAddr":"192.0.2.2:80","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200,"DownstreamContentSize":0,"RouterName":"r","ServiceName":"s","Duration":1}`),
			wantCount: 1,
		},
		{
			name:      "JSON missing client address",
			line:      []byte(`{"RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200}`),
			wantCount: 0,
		},
		{
			name:      "malformed JSON",
			line:      []byte(`{not valid json`),
			wantCount: 0,
		},
		{
			name:      "ANSI escape in UA",
			line:      []byte("192.0.2.1 - - [26/Jun/2026:12:00:01 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"\x1b[31mEvil\x1b[0m\" 1 \"r@docker\" \"http://b:80\" 2ms"),
			wantCount: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := p.Parse(sdk.RawLine{
				Source: "traefik:traefik",
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

// TestTraefikParser_XFF verifies that X-Forwarded-For is used only when the
// connecting address is a configured trusted proxy (anti-spoofing).
func TestTraefikParser_XFF(t *testing.T) {
	trustedPrefix := netip.MustParsePrefix("10.0.0.0/8")
	cfg := parser.TraefikConfig{TrustedProxies: []netip.Prefix{trustedPrefix}}
	p := parser.NewTraefikParser(discardLogger(), cfg)

	t.Run("trusted proxy: XFF used", func(t *testing.T) {
		// ClientHost is 10.0.0.1 (trusted); real client is 203.0.113.99 via XFF.
		line := sdk.RawLine{
			Source: "traefik:traefik",
			Line:   []byte(`{"ClientAddr":"10.0.0.1:5050","ClientHost":"10.0.0.1","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200,"DownstreamContentSize":0,"RouterName":"r","ServiceName":"s","Duration":1,"request_X-Forwarded-For":"203.0.113.99"}`),
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

	t.Run("untrusted client: XFF ignored", func(t *testing.T) {
		// ClientHost is NOT in trusted proxies; XFF header must be ignored.
		line := sdk.RawLine{
			Source: "traefik:traefik",
			Line:   []byte(`{"ClientAddr":"198.51.100.5:5050","ClientHost":"198.51.100.5","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200,"DownstreamContentSize":0,"RouterName":"r","ServiceName":"s","Duration":1,"request_X-Forwarded-For":"1.2.3.4"}`),
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
		pNoTrust := parser.NewTraefikParser(discardLogger(), parser.TraefikConfig{})
		line := sdk.RawLine{
			Source: "traefik:traefik",
			Line:   []byte(`{"ClientAddr":"10.0.0.1:5050","ClientHost":"10.0.0.1","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200,"DownstreamContentSize":0,"RouterName":"r","ServiceName":"s","Duration":1,"request_X-Forwarded-For":"1.2.3.4"}`),
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

	t.Run("multi-hop XFF: leftmost non-trusted", func(t *testing.T) {
		line := sdk.RawLine{
			Source: "traefik:traefik",
			Line:   []byte(`{"ClientHost":"10.0.0.5","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":200,"DownstreamContentSize":0,"RouterName":"r","ServiceName":"s","Duration":1,"request_X-Forwarded-For":"203.0.113.7, 10.0.0.99, 10.0.0.5"}`),
			At:     time.Now(),
		}
		evs, err := p.Parse(line)
		if err != nil || len(evs) != 1 {
			t.Fatalf("expected 1 event, got %d (err=%v)", len(evs), err)
		}
		if evs[0].SourceIP.String() != "203.0.113.7" {
			t.Errorf("SourceIP: got %q, want 203.0.113.7", evs[0].SourceIP)
		}
	})
}

// TestTraefikParser_FieldCaps verifies that long path/UA/router/service fields
// are truncated to their respective caps.
func TestTraefikParser_FieldCaps(t *testing.T) {
	p := parser.NewTraefikParser(discardLogger(), parser.TraefikConfig{})

	longUA := makeLongLine(600)
	rawLine := []byte(`192.0.2.1 - - [26/Jun/2026:12:00:01 +0000] "GET /path HTTP/1.1" 200 0 "-" "` + longUA + `" 1 "r@docker" "http://b:80" 2ms`)
	if len(rawLine) > 4096 {
		t.Skip("constructed line exceeds line cap; adjust test")
	}

	evs, err := p.Parse(sdk.RawLine{
		Source: "traefik:traefik",
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
