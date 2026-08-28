// SPDX-License-Identifier: AGPL-3.0-only

package parser

// Tests for the Vaultwarden parser (issue #191).

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

func newTestVaultwardenParser() *VaultwardenParser {
	return NewVaultwardenParser(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func parseVWLine(t *testing.T, line string) []sdk.Event {
	t.Helper()
	evs, err := newTestVaultwardenParser().Parse(sdk.RawLine{
		Source: "docker:vaultwarden",
		Line:   []byte(line),
		At:     time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	return evs
}

func TestVaultwardenParse_TableDriven(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		line   string
		kind   string
		ip     string
		fields map[string]string
	}{
		{
			name: "password fail with username",
			line: "[2026-08-25 14:00:00.101][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 203.0.113.100. Username: admin@example.com.",
			kind: "vaultwarden_auth_fail", ip: "203.0.113.100",
			fields: map[string]string{"user": "admin@example.com"},
		},
		{
			name: "password fail ipv6",
			line: "[2026-08-25 14:00:04.303][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 2001:db8::aa. Username: user@example.com.",
			kind: "vaultwarden_auth_fail", ip: "2001:db8::aa",
			fields: map[string]string{"user": "user@example.com"},
		},
		{
			name: "totp fail",
			line: "[2026-08-25 14:00:06.404][vaultwarden::api::identity][ERROR] Invalid TOTP code! Server time: 2026-08-25 14:00:06 UTC IP: 203.0.113.101",
			kind: "vaultwarden_auth_fail", ip: "203.0.113.101",
			fields: map[string]string{"mfa": "totp"},
		},
		{name: "successful login is silent", line: "[2026-08-25 14:00:10.707][response][INFO] (login) POST /identity/connect/token => 200 OK"},
		{name: "unrelated error", line: "[2026-08-25 14:00:11][vaultwarden::api::core][ERROR] Some other error without an address"},
		{name: "invalid ip", line: "Username or password is incorrect. Try again. IP: not.an.ip.addr. Username: x."},
		{name: "empty", line: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evs := parseVWLine(t, tc.line)
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

func TestVaultwardenParse_Fixtures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file    string
		source  string
		want    int
		wantIPs map[string]int
	}{
		{
			file: "vaultwarden.log", source: "file:/var/log/vaultwarden.log", want: 4,
			wantIPs: map[string]int{"203.0.113.100": 2, "2001:db8::aa": 1, "203.0.113.101": 1},
		},
		{
			file: "docker.log", source: "docker:vaultwarden", want: 2,
			wantIPs: map[string]int{"203.0.113.110": 1, "203.0.113.111": 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "vaultwarden", tc.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			p := newTestVaultwardenParser()
			got := 0
			gotIPs := map[string]int{}
			for _, line := range strings.Split(string(data), "\n") {
				evs, err := p.Parse(sdk.RawLine{Source: tc.source, Line: []byte(line), At: time.Now()})
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				for _, ev := range evs {
					if ev.Kind != "vaultwarden_auth_fail" {
						t.Errorf("unexpected kind %q", ev.Kind)
					}
					got++
					gotIPs[ev.SourceIP.String()]++
				}
			}
			if got != tc.want {
				t.Errorf("events = %d, want %d", got, tc.want)
			}
			for ip, n := range tc.wantIPs {
				if gotIPs[ip] != n {
					t.Errorf("ip %s = %d, want %d (all: %v)", ip, gotIPs[ip], n, gotIPs)
				}
			}
		})
	}
}

func TestVaultwardenMatches(t *testing.T) {
	t.Parallel()
	yes := []string{
		"vaultwarden:whatever",
		"docker:vaultwarden",
		"docker:my-vaultwarden-1",
		"docker:Vaultwarden",
		"file:/var/log/vaultwarden.log",
		"/var/log/vaultwarden.log",
	}
	no := []string{
		"docker:bitwarden-rs-old", // different name — explicit override covers renames
		"docker:nginx",
		"journald:vaultwarden", // no journald convention for vaultwarden
		"nginx:/var/log/vaultwarden.log",
		"file:/var/log/nginx/access.log",
	}
	p := newTestVaultwardenParser()
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

func TestVaultwardenParse_CapsAndHostileInput(t *testing.T) {
	t.Parallel()
	huge := "Username or password is incorrect. Try again. IP: 203.0.113.5. Username: " + strings.Repeat("A", maxLineBytes)
	if evs := parseVWLine(t, huge); len(evs) != 0 {
		t.Fatalf("oversized line must be skipped, got %+v", evs)
	}
	line := "Username or password is incorrect. Try again. IP: 203.0.113.5. Username: " + strings.Repeat("u", 500) + "."
	evs := parseVWLine(t, line)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	if got := len(evs[0].Fields["user"]); got != maxVaultwardenUserBytes {
		t.Errorf("user length = %d, want capped at %d", got, maxVaultwardenUserBytes)
	}
	for _, hostile := range []string{
		"\x1b[31mUsername or password is incorrect. Try again. IP: 203.0.113.5.\x1b[0m",
		"Username or password is incorrect. Try again. IP: 203.0.113.5.\r\nINJECTED",
		string([]byte{0x00, 0xff, 0xfe}),
	} {
		_ = parseVWLine(t, hostile)
	}
}
