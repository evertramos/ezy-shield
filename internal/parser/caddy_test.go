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

// runCaddyGoldenTest parses every line in fixtureFile and compares resulting
// events against the expected events in goldenFile.
func runCaddyGoldenTest(t *testing.T, fixtureFile, goldenFile, origin string, cfg parser.CaddyConfig) {
	t.Helper()

	p := parser.NewCaddyParser(discardLogger(), cfg)

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

// TestCaddyParser_GoldenJSON tests parsing of Caddy v2 JSON access logs.
func TestCaddyParser_GoldenJSON(t *testing.T) {
	runCaddyGoldenTest(t,
		"../../fixtures/caddy/json.log",
		"../../fixtures/caddy/json.log.golden.json",
		"caddy:caddy",
		parser.CaddyConfig{},
	)
}

// TestCaddyParser_GoldenCLF tests parsing of Caddy CLF (Apache common) format.
func TestCaddyParser_GoldenCLF(t *testing.T) {
	runCaddyGoldenTest(t,
		"../../fixtures/caddy/clf.log",
		"../../fixtures/caddy/clf.log.golden.json",
		"file:/var/log/caddy/access.log",
		parser.CaddyConfig{},
	)
}

// TestCaddyParser_GoldenDockerJSON tests automatic unwrapping of Docker
// json-file log wrappers around Caddy CLF and JSON lines.
func TestCaddyParser_GoldenDockerJSON(t *testing.T) {
	runCaddyGoldenTest(t,
		"../../fixtures/caddy/docker_json.log",
		"../../fixtures/caddy/docker_json.log.golden.json",
		"caddy:caddy",
		parser.CaddyConfig{},
	)
}

// TestCaddyParser_Matches verifies the Matches predicate.
func TestCaddyParser_Matches(t *testing.T) {
	p := parser.NewCaddyParser(discardLogger(), parser.CaddyConfig{})

	cases := []struct {
		source string
		want   bool
	}{
		{"journald:caddy", true},
		{"file:/var/log/caddy/access.log", true},
		{"caddy:caddy", true},
		{"caddy:edge-proxy", true},
		{"caddy:/var/log/custom/access.log", true},
		{"journald:nginx", false},
		{"file:/var/log/auth.log", false},
		{"nginx:proxy-web", false},
		{"ssh:mycontainer", false},
		{"traefik:traefik", false},
		{"", false},
	}
	for _, tc := range cases {
		got := p.Matches(tc.source)
		if got != tc.want {
			t.Errorf("Matches(%q) = %v, want %v", tc.source, got, tc.want)
		}
	}
}

// TestCaddyParser_EdgeCases covers table-driven edge-case inputs.
func TestCaddyParser_EdgeCases(t *testing.T) {
	p := parser.NewCaddyParser(discardLogger(), parser.CaddyConfig{})

	// JSON-encoded ESC is a six-byte sequence in the raw JSON; json.Unmarshal
	// decodes it into a single 0x1B byte in the resulting Go string.
	ansiJSON := "{\"request\":{\"remote_ip\":\"192.0.2.3\",\"method\":\"GET\",\"uri\":\"/\",\"host\":\"x\",\"headers\":{\"User-Agent\":[\"\\u001b[31mEvil\\u001b[0m\"]}},\"status\":200}"

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
			line:      []byte(`192.0.2.1 - - [26/Jun/2026:12:00:01 +0000] "GET / HTTP/2.0" 200 0`),
			wantCount: 1,
		},
		{
			name:      "valid CLF IPv6",
			line:      []byte(`2001:db8::1 - - [26/Jun/2026:12:00:01 +0000] "GET / HTTP/2.0" 200 0`),
			wantCount: 1,
		},
		{
			name:      "invalid IP in CLF",
			line:      []byte(`not-an-ip - - [26/Jun/2026:12:00:01 +0000] "GET / HTTP/2.0" 200 0`),
			wantCount: 0,
		},
		{
			name:      "valid JSON line",
			line:      []byte(`{"request":{"remote_ip":"192.0.2.2","method":"GET","uri":"/","host":"x","headers":{"User-Agent":["curl"]}},"status":200,"size":0,"duration":0.001}`),
			wantCount: 1,
		},
		{
			name:      "JSON missing request object",
			line:      []byte(`{"status":200,"size":0,"duration":0.001}`),
			wantCount: 0,
		},
		{
			name:      "JSON missing remote_ip",
			line:      []byte(`{"request":{"method":"GET","uri":"/","host":"x"},"status":200}`),
			wantCount: 0,
		},
		{
			name:      "JSON invalid remote_ip",
			line:      []byte(`{"request":{"remote_ip":"not-an-ip","method":"GET","uri":"/","host":"x"},"status":200}`),
			wantCount: 0,
		},
		{
			name:      "malformed JSON",
			line:      []byte(`{not valid json`),
			wantCount: 0,
		},
		{
			// JSON encoded  in UA — legal JSON, parser must accept.
			name:      "ANSI escape in UA (JSON-encoded)",
			line:      []byte(ansiJSON),
			wantCount: 1,
		},
		{
			name:      "ANSI escape in CLF path (raw byte)",
			line:      []byte("192.0.2.7 - - [26/Jun/2026:12:00:01 +0000] \"GET /\x1b[31mevil\x1b[0m HTTP/2.0\" 200 0"),
			wantCount: 1,
		},
		{
			name:      "JSON with bracketed IPv6 in remote_ip (parser strips brackets)",
			line:      []byte(`{"request":{"remote_ip":"[2001:db8::5]","method":"GET","uri":"/","host":"x"},"status":200}`),
			wantCount: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := p.Parse(sdk.RawLine{
				Source: "caddy:caddy",
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

// TestCaddyParser_HeadersCase verifies header lookup tolerates non-canonical
// (lowercase) header names from a custom Caddy header_names config.
func TestCaddyParser_HeadersCase(t *testing.T) {
	p := parser.NewCaddyParser(discardLogger(), parser.CaddyConfig{})

	line := []byte(`{"request":{"remote_ip":"192.0.2.9","method":"GET","uri":"/","host":"x","headers":{"user-agent":["lowercased-ua"]}},"status":200,"size":0,"duration":0.001}`)
	evs, err := p.Parse(sdk.RawLine{
		Source: "caddy:caddy",
		Line:   line,
		At:     time.Now(),
	})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0].Fields["ua"] != "lowercased-ua" {
		t.Errorf("ua: got %q, want %q", evs[0].Fields["ua"], "lowercased-ua")
	}
}

// TestCaddyParser_XFF verifies that X-Forwarded-For is used only when the
// connecting address is a configured trusted proxy (anti-spoofing).
func TestCaddyParser_XFF(t *testing.T) {
	trustedPrefix := netip.MustParsePrefix("10.0.0.0/8")
	cfg := parser.CaddyConfig{TrustedProxies: []netip.Prefix{trustedPrefix}}
	p := parser.NewCaddyParser(discardLogger(), cfg)

	t.Run("trusted proxy: XFF used", func(t *testing.T) {
		// remote_ip is 10.0.0.1 (trusted); real client is 203.0.113.99 via XFF.
		line := sdk.RawLine{
			Source: "caddy:caddy",
			Line:   []byte(`{"request":{"remote_ip":"10.0.0.1","method":"GET","uri":"/","host":"x","headers":{"User-Agent":["test"],"X-Forwarded-For":["203.0.113.99"]}},"status":200,"size":0,"duration":0.001}`),
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
		line := sdk.RawLine{
			Source: "caddy:caddy",
			Line:   []byte(`{"request":{"remote_ip":"198.51.100.5","method":"GET","uri":"/","host":"x","headers":{"User-Agent":["attacker"],"X-Forwarded-For":["1.2.3.4"]}},"status":200,"size":0,"duration":0.001}`),
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
		pNoTrust := parser.NewCaddyParser(discardLogger(), parser.CaddyConfig{})
		line := sdk.RawLine{
			Source: "caddy:caddy",
			Line:   []byte(`{"request":{"remote_ip":"10.0.0.1","method":"GET","uri":"/","host":"x","headers":{"User-Agent":["test"],"X-Forwarded-For":["1.2.3.4"]}},"status":200,"size":0,"duration":0.001}`),
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
			Source: "caddy:caddy",
			Line:   []byte(`{"request":{"remote_ip":"10.0.0.5","method":"GET","uri":"/","host":"x","headers":{"X-Forwarded-For":["203.0.113.7, 10.0.0.99, 10.0.0.5"]}},"status":200,"size":0,"duration":0.001}`),
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

// TestCaddyParser_FieldCaps verifies that long UA / host fields are truncated.
func TestCaddyParser_FieldCaps(t *testing.T) {
	p := parser.NewCaddyParser(discardLogger(), parser.CaddyConfig{})

	longUA := makeLongLine(600)
	longHost := makeLongLine(400)
	line := []byte(`{"request":{"remote_ip":"192.0.2.1","method":"GET","uri":"/","host":"` + longHost + `","headers":{"User-Agent":["` + longUA + `"]}},"status":200,"size":0,"duration":0.001}`)
	if len(line) > 4096 {
		t.Skip("constructed line exceeds line cap; adjust test")
	}

	evs, err := p.Parse(sdk.RawLine{
		Source: "caddy:caddy",
		Line:   line,
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
	if len(evs[0].Fields["host"]) > 256 {
		t.Errorf("host field exceeds 256 bytes: %d", len(evs[0].Fields["host"]))
	}
}
