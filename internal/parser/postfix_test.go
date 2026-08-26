package parser

// Tests for the Postfix smtpd parser (issue #188): table-driven cases,
// fixture replays (Debian bare-metal + mailcow docker json-file) with golden
// expectations, source matching, caps, and hostile input.

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func newTestPostfixParser() *PostfixParser {
	return NewPostfixParser(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func parsePostfixLine(t *testing.T, line string) []sdk.Event {
	t.Helper()
	evs, err := newTestPostfixParser().Parse(sdk.RawLine{
		Source: "journald:postfix",
		Line:   []byte(line),
		At:     time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	return evs
}

func TestPostfixParse_TableDriven(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		line   string
		kind   string // "" = no event
		ip     string
		fields map[string]string
	}{
		{
			name: "sasl login fail",
			line: "Aug 25 12:00:02 mail postfix/smtpd[3121]: warning: unknown[203.0.113.50]: SASL LOGIN authentication failed: UGFzc3dvcmQ6",
			kind: "smtp_auth_fail", ip: "203.0.113.50",
			fields: map[string]string{"method": "LOGIN"},
		},
		{
			name: "sasl fail with rDNS hostname (hostname ignored, IP authoritative)",
			line: "Aug 25 12:00:06 mail postfix/smtpd[3121]: warning: host50.example.net[203.0.113.50]: SASL CRAM-MD5 authentication failed: authentication failure",
			kind: "smtp_auth_fail", ip: "203.0.113.50",
			fields: map[string]string{"method": "CRAM-MD5"},
		},
		{
			name: "sasl fail ipv6",
			line: "warning: unknown[2001:db8::66]: SASL LOGIN authentication failed: x",
			kind: "smtp_auth_fail", ip: "2001:db8::66",
		},
		{
			name: "sasl fail bracketed IPv6: prefix form",
			line: "warning: unknown[IPv6:2001:db8::67]: SASL PLAIN authentication failed: x",
			kind: "smtp_auth_fail", ip: "2001:db8::67",
		},
		{
			name: "relay denied",
			line: "Aug 25 12:00:08 mail postfix/smtpd[3121]: NOQUEUE: reject: RCPT from unknown[203.0.113.51]: 554 5.7.1 <spam@victim.example>: Relay access denied; from=<b@evil.example> to=<spam@victim.example> proto=ESMTP helo=<evil.example>",
			kind: "smtp_relay_denied", ip: "203.0.113.51",
			fields: map[string]string{"reject": "relay"},
		},
		{
			name: "relay denied with sasl_username",
			line: "NOQUEUE: reject: RCPT from relay51.example[203.0.113.51]: 554 5.7.1 <x@y.example>: Relay access denied; from=<a@b.example> to=<x@y.example> proto=ESMTP helo=<zzz>, sasl_username=admin",
			kind: "smtp_relay_denied", ip: "203.0.113.51",
			fields: map[string]string{"reject": "relay", "user": "admin"},
		},
		{
			name: "too many errors",
			line: "too many errors after RCPT from unknown[203.0.113.52]",
			kind: "smtp_abuse", ip: "203.0.113.52",
			fields: map[string]string{"abuse": "too_many_errors"},
		},
		{
			name: "lost connection after AUTH",
			line: "Aug 25 12:00:12 mail postfix/smtpd[3121]: lost connection after AUTH from unknown[203.0.113.53]",
			kind: "smtp_abuse", ip: "203.0.113.53",
			fields: map[string]string{"abuse": "lost_connection_after_auth"},
		},
		{name: "benign connect", line: "connect from mail.legit.example[198.51.100.9]"},
		{name: "benign disconnect", line: "disconnect from unknown[203.0.113.50] ehlo=1 auth=0/3 quit=1 commands=2/5"},
		{name: "ordinary reject is not relay abuse", line: "NOQUEUE: reject: RCPT from unknown[203.0.113.54]: 550 5.1.1 <nouser@here.example>: Recipient address rejected: User unknown"},
		{name: "empty", line: ""},
		{name: "garbage", line: "postfix/smtpd[1]: warning: weird line with no bracket"},
		{name: "invalid ip in bracket", line: "warning: unknown[not-an-ip]: SASL LOGIN authentication failed: x"},
		// A crafted hostname faking extra brackets does not yield a
		// parseable identity — the safe outcome is NO event (never a ban
		// keyed on an attacker-chosen string).
		{name: "spoofed hostname with fake bracket ip", line: "warning: fake[203.0.113.99]suffix[nope]: SASL LOGIN authentication failed: x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evs := parsePostfixLine(t, tc.line)
			if tc.kind == "" {
				if len(evs) != 0 {
					t.Fatalf("expected no event, got %+v", evs)
				}
				return
			}
			if len(evs) != 1 {
				t.Fatalf("events = %d, want 1", len(evs))
			}
			ev := evs[0]
			if ev.Kind != tc.kind {
				t.Errorf("kind = %q, want %q", ev.Kind, tc.kind)
			}
			if ev.SourceIP != netip.MustParseAddr(tc.ip) {
				t.Errorf("ip = %s, want %s", ev.SourceIP, tc.ip)
			}
			for k, v := range tc.fields {
				if ev.Fields[k] != v {
					t.Errorf("field %s = %q, want %q", k, ev.Fields[k], v)
				}
			}
		})
	}
}

// TestPostfixParse_Fixtures replays the real-world-shaped fixtures and
// asserts the golden event counts per kind and per IP.
func TestPostfixParse_Fixtures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file      string
		source    string
		wantKinds map[string]int
		wantIPs   map[string]int
	}{
		{
			file:   "debian-mail.log",
			source: "file:/var/log/mail.log",
			wantKinds: map[string]int{
				"smtp_auth_fail": 5, "smtp_relay_denied": 2, "smtp_abuse": 2,
			},
			wantIPs: map[string]int{
				"203.0.113.50": 3, "203.0.113.51": 2, "203.0.113.52": 1,
				"203.0.113.53": 1, "2001:db8::66": 1, "2001:db8::67": 1,
			},
		},
		{
			file:   "mailcow-docker.log",
			source: "postfix:mailcow-postfix",
			wantKinds: map[string]int{
				"smtp_auth_fail": 1, "smtp_relay_denied": 1, "smtp_abuse": 1,
			},
			wantIPs: map[string]int{
				"203.0.113.60": 1, "203.0.113.61": 1, "203.0.113.62": 1,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "postfix", tc.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			p := newTestPostfixParser()
			gotKinds := map[string]int{}
			gotIPs := map[string]int{}
			for _, line := range strings.Split(string(data), "\n") {
				evs, err := p.Parse(sdk.RawLine{Source: tc.source, Line: []byte(line), At: time.Now()})
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				for _, ev := range evs {
					gotKinds[ev.Kind]++
					gotIPs[ev.SourceIP.String()]++
				}
			}
			for k, n := range tc.wantKinds {
				if gotKinds[k] != n {
					t.Errorf("kind %s = %d, want %d (all: %v)", k, gotKinds[k], n, gotKinds)
				}
			}
			if len(gotKinds) != len(tc.wantKinds) {
				t.Errorf("unexpected kinds: %v", gotKinds)
			}
			for ip, n := range tc.wantIPs {
				if gotIPs[ip] != n {
					t.Errorf("ip %s = %d, want %d (all: %v)", ip, gotIPs[ip], n, gotIPs)
				}
			}
		})
	}
}

func TestPostfixMatches(t *testing.T) {
	t.Parallel()
	yes := []string{
		"postfix:whatever",
		"journald:postfix",
		"journald:postfix.service",
		"journald:postfix@-.service",
		"journald:postfix@mailcow",
		"file:/var/log/mail.log",
		"file:/var/log/maillog",
		"/var/log/mail.log",
	}
	no := []string{
		"journald:sshd",
		"journald:dovecot",
		"nginx:/var/log/mail.log",
		"file:/var/log/nginx/access.log",
		"journald:postfixish",
	}
	p := newTestPostfixParser()
	for _, s := range yes {
		if !p.Matches(s) {
			t.Errorf("Matches(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if p.Matches(s) {
			t.Errorf("Matches(%q) = true, want false", s)
		}
	}
}

func TestPostfixParse_CapsAndHostileInput(t *testing.T) {
	t.Parallel()
	// Oversized line: skipped entirely.
	huge := "warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: " + strings.Repeat("A", maxLineBytes)
	if evs := parsePostfixLine(t, huge); len(evs) != 0 {
		t.Fatalf("oversized line must be skipped, got %+v", evs)
	}
	// Oversized sasl_username is capped, not dropped.
	line := "NOQUEUE: reject: RCPT from unknown[203.0.113.5]: 554 5.7.1 <a@b.example>: Relay access denied; sasl_username=" + strings.Repeat("u", 500)
	evs := parsePostfixLine(t, line)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	if got := len(evs[0].Fields["user"]); got != maxPostfixUserBytes {
		t.Errorf("user field length = %d, want capped at %d", got, maxPostfixUserBytes)
	}
	// ANSI/CRLF garbage never panics and produces nothing.
	for _, hostile := range []string{
		"\x1b[31mwarning: unknown[203.0.113.5]\x1b[0m",
		"warning: unknown[203.0.113.5]\r\nInjected: SASL LOGIN authentication failed",
		string([]byte{0x00, 0xff, 0xfe, '['}),
	} {
		_ = parsePostfixLine(t, hostile)
	}
}
