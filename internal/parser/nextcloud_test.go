// SPDX-License-Identifier: AGPL-3.0-only

package parser

// Tests for the Nextcloud parser (issue #192).

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

func newTestNextcloudParser() *NextcloudParser {
	return NewNextcloudParser(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func parseNCLine(t *testing.T, line string) []sdk.Event {
	t.Helper()
	evs, err := newTestNextcloudParser().Parse(sdk.RawLine{
		Source: "file:/var/www/nextcloud/data/nextcloud.log",
		Line:   []byte(line),
		At:     time.Date(2026, 8, 25, 15, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	return evs
}

func TestNextcloudParse_TableDriven(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		line   string
		kind   string
		ip     string
		fields map[string]string
	}{
		{
			name: "core login failed",
			line: `{"remoteAddr":"203.0.113.130","app":"core","message":"Login failed: 'admin' (Remote IP: '203.0.113.130')"}`,
			kind: "nextcloud_auth_fail", ip: "203.0.113.130",
			fields: map[string]string{"user": "admin"},
		},
		{
			name: "ipv6 remoteAddr",
			line: `{"remoteAddr":"2001:db8::cc","app":"core","message":"Login failed: 'u@e.example' (Remote IP: '2001:db8::cc')"}`,
			kind: "nextcloud_auth_fail", ip: "2001:db8::cc",
			fields: map[string]string{"user": "u@e.example"},
		},
		{
			name: "admin_audit login attempt failed",
			line: `{"remoteAddr":"203.0.113.131","app":"admin_audit","message":"Login attempt failed for user: guest"}`,
			kind: "nextcloud_auth_fail", ip: "203.0.113.131",
		},
		{name: "successful login is silent", line: `{"remoteAddr":"198.51.100.9","app":"core","message":"Login successful: 'evert'"}`},
		{name: "unrelated app with failure-looking message", line: `{"remoteAddr":"203.0.113.5","app":"files","message":"Login failed: not really, wrong app"}`},
		{name: "failure without address is dropped", line: `{"remoteAddr":"","app":"core","message":"Login failed: 'x'"}`},
		{name: "invalid remoteAddr", line: `{"remoteAddr":"proxy.internal","app":"core","message":"Login failed: 'x'"}`},
		{name: "malformed json", line: `{"remoteAddr":"203.0.113.5","app":"core","message":"Login failed`},
		{name: "not json", line: "plain text line"},
		{name: "empty", line: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evs := parseNCLine(t, tc.line)
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

func TestNextcloudParse_Fixtures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file    string
		source  string
		want    int
		wantIPs map[string]int
	}{
		{
			file: "nextcloud.log", source: "file:/var/www/nextcloud/data/nextcloud.log", want: 4,
			wantIPs: map[string]int{"203.0.113.130": 2, "2001:db8::cc": 1, "203.0.113.131": 1},
		},
		{
			file: "docker.log", source: "docker:nextcloud-app-1", want: 1,
			wantIPs: map[string]int{"203.0.113.140": 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "nextcloud", tc.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			p := newTestNextcloudParser()
			got := 0
			gotIPs := map[string]int{}
			for _, line := range strings.Split(string(data), "\n") {
				evs, err := p.Parse(sdk.RawLine{Source: tc.source, Line: []byte(line), At: time.Now()})
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				for _, ev := range evs {
					if ev.Kind != "nextcloud_auth_fail" {
						t.Errorf("unexpected kind %q", ev.Kind)
					}
					got++
					gotIPs[ev.SourceIP.String()]++
				}
			}
			if got != tc.want {
				t.Errorf("events = %d, want %d (ips: %v)", got, tc.want, gotIPs)
			}
			for ip, n := range tc.wantIPs {
				if gotIPs[ip] != n {
					t.Errorf("ip %s = %d, want %d (all: %v)", ip, gotIPs[ip], n, gotIPs)
				}
			}
		})
	}
}

func TestNextcloudMatches(t *testing.T) {
	t.Parallel()
	yes := []string{
		"nextcloud:whatever",
		"docker:nextcloud",
		"docker:nextcloud-app-1",
		"file:/var/www/nextcloud/data/nextcloud.log",
		"/var/www/nextcloud/data/nextcloud.log",
	}
	no := []string{
		"docker:nginx",
		"journald:nextcloud",
		"nginx:/var/www/nextcloud/data/nextcloud.log",
		"file:/var/log/nginx/access.log",
	}
	p := newTestNextcloudParser()
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

func TestNextcloudParse_CapsAndHostileInput(t *testing.T) {
	t.Parallel()
	// Oversized JSON is refused BEFORE decode.
	huge := `{"remoteAddr":"203.0.113.5","app":"core","message":"Login failed: '` + strings.Repeat("A", maxLineBytes) + `'"}`
	if evs := parseNCLine(t, huge); len(evs) != 0 {
		t.Fatalf("oversized line must be skipped, got %+v", evs)
	}
	// Oversized username capped, not dropped.
	line := `{"remoteAddr":"203.0.113.5","app":"core","message":"Login failed: '` + strings.Repeat("u", 500) + `'"}`
	evs := parseNCLine(t, line)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	if got := len(evs[0].Fields["user"]); got != maxNextcloudUserBytes {
		t.Errorf("user length = %d, want capped at %d", got, maxNextcloudUserBytes)
	}
	// Deeply nested unknown fields, truncated JSON, binary: never panic.
	for _, hostile := range []string{
		`{"remoteAddr":"203.0.113.5","app":"core","message":"Login failed: 'x'","extra":` + strings.Repeat(`{"a":`, 400) + `1` + strings.Repeat(`}`, 400) + `}`,
		`{"remoteAddr":"203.0.113.5","app":"core","mess`,
		string([]byte{'{', 0x00, 0xff}),
	} {
		_ = parseNCLine(t, hostile)
	}
}
