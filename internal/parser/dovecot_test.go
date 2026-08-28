// SPDX-License-Identifier: AGPL-3.0-only

package parser

// Tests for the Dovecot IMAP/POP3 parser (issue #189): table-driven cases,
// fixture replays with golden expectations, source matching, caps, and
// hostile input.

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

func newTestDovecotParser() *DovecotParser {
	return NewDovecotParser(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func parseDovecotLine(t *testing.T, line string) []sdk.Event {
	t.Helper()
	evs, err := newTestDovecotParser().Parse(sdk.RawLine{
		Source: "journald:dovecot",
		Line:   []byte(line),
		At:     time.Date(2026, 8, 25, 13, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	return evs
}

func TestDovecotParse_TableDriven(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		line   string
		kind   string // "" = no event
		ip     string
		fields map[string]string
	}{
		{
			name: "imap aborted auth fail",
			line: "Aug 25 13:00:02 mail dovecot: imap-login: Aborted login (auth failed, 3 attempts in 6 secs): user=<admin>, method=PLAIN, rip=203.0.113.70, lip=198.51.100.1, TLS, session=<x1>",
			kind: "imap_auth_fail", ip: "203.0.113.70",
			fields: map[string]string{"proto": "imap", "attempts": "3", "user": "admin", "method": "PLAIN"},
		},
		{
			name: "pop3 disconnected auth fail",
			line: "dovecot: pop3-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<root>, method=PLAIN, rip=203.0.113.71, lip=198.51.100.1",
			kind: "imap_auth_fail", ip: "203.0.113.71",
			fields: map[string]string{"proto": "pop3", "attempts": "1", "user": "root"},
		},
		{
			name: "ipv6 rip",
			line: "dovecot: imap-login: Aborted login (auth failed, 5 attempts in 11 secs): user=<info>, method=LOGIN, rip=2001:db8::71, lip=2001:db8::1",
			kind: "imap_auth_fail", ip: "2001:db8::71",
			fields: map[string]string{"method": "LOGIN"},
		},
		{
			name: "no-auth probe is the distinct lower-signal kind",
			line: "dovecot: imap-login: Disconnected (no auth attempts in 5 secs): rip=203.0.113.72, lip=198.51.100.1, TLS handshaking",
			kind: "imap_probe", ip: "203.0.113.72",
			fields: map[string]string{"proto": "imap"},
		},
		{
			name: "pop3 probe",
			line: "dovecot: pop3-login: Disconnected (no auth attempts in 0 secs): rip=203.0.113.72, lip=198.51.100.1",
			kind: "imap_probe", ip: "203.0.113.72",
			fields: map[string]string{"proto": "pop3"},
		},
		{name: "successful login is silent", line: "dovecot: imap-login: Login: user=<evert>, method=PLAIN, rip=198.51.100.9, lip=198.51.100.1, TLS"},
		{name: "auth fail without rip is dropped", line: "dovecot: imap-login: Aborted login (auth failed, 2 attempts in 3 secs): user=<x>, method=PLAIN, lip=198.51.100.1"},
		{name: "invalid rip is dropped", line: "dovecot: imap-login: Aborted login (auth failed, 2 attempts in 3 secs): rip=zzz.bad, lip=198.51.100.1"},
		{name: "lip alone never becomes the identity", line: "dovecot: imap-login: Disconnected (no auth attempts in 1 secs): lip=198.51.100.1"},
		{name: "unrelated dovecot line", line: "dovecot: master: Warning: Killed with signal 15"},
		{name: "empty", line: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evs := parseDovecotLine(t, tc.line)
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

func TestDovecotParse_Fixtures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file      string
		source    string
		wantKinds map[string]int
		wantIPs   map[string]int
	}{
		{
			file:      "debian-dovecot.log",
			source:    "file:/var/log/dovecot.log",
			wantKinds: map[string]int{"imap_auth_fail": 3, "imap_probe": 2},
			wantIPs: map[string]int{
				"203.0.113.70": 1, "203.0.113.71": 1, "2001:db8::71": 1, "203.0.113.72": 2,
			},
		},
		{
			file:      "mailcow-docker.log",
			source:    "dovecot:mailcow-dovecot",
			wantKinds: map[string]int{"imap_auth_fail": 1, "imap_probe": 1},
			wantIPs:   map[string]int{"203.0.113.80": 1, "203.0.113.81": 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "dovecot", tc.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			p := newTestDovecotParser()
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

func TestDovecotMatches(t *testing.T) {
	t.Parallel()
	yes := []string{
		"dovecot:whatever",
		"journald:dovecot",
		"journald:dovecot.service",
		"file:/var/log/dovecot.log",
		"/var/log/dovecot.log",
	}
	no := []string{
		"journald:dovecot-submission",
		"journald:postfix",
		// mail.log routes to the postfix parser (first-match routing) —
		// shared-log setups use the journald unit or an explicit override.
		"file:/var/log/mail.log",
		"nginx:/var/log/dovecot.log",
		"journald:sshd",
	}
	p := newTestDovecotParser()
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

func TestDovecotParse_CapsAndHostileInput(t *testing.T) {
	t.Parallel()
	huge := "dovecot: imap-login: Aborted login (auth failed, 1 attempts in 1 secs): rip=203.0.113.5, " + strings.Repeat("A", maxLineBytes)
	if evs := parseDovecotLine(t, huge); len(evs) != 0 {
		t.Fatalf("oversized line must be skipped, got %+v", evs)
	}
	// Oversized user is capped, not dropped.
	line := "dovecot: imap-login: Aborted login (auth failed, 1 attempts in 1 secs): user=<" +
		strings.Repeat("u", 500) + ">, method=PLAIN, rip=203.0.113.5"
	evs := parseDovecotLine(t, line)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	if got := len(evs[0].Fields["user"]); got != maxDovecotUserBytes {
		t.Errorf("user field length = %d, want capped at %d", got, maxDovecotUserBytes)
	}
	for _, hostile := range []string{
		"\x1b[31mdovecot: imap-login: Aborted login (auth failed, 1 attempts in 1 secs): rip=203.0.113.5\x1b[0m",
		"dovecot: imap-login: Aborted login (auth failed, 1 attempts in 1 secs): rip=203.0.113.5\r\nINJECTED",
		string([]byte{0x00, 0xff, 0xfe}),
	} {
		_ = parseDovecotLine(t, hostile)
	}
}
