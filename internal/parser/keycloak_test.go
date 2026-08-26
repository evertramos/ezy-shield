package parser

// Tests for the Keycloak parser (issue #193).

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

import "github.com/evertramos/ezy-shield/pkg/sdk"

func newTestKeycloakParser() *KeycloakParser {
	return NewKeycloakParser(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func parseKCLine(t *testing.T, line string) []sdk.Event {
	t.Helper()
	evs, err := newTestKeycloakParser().Parse(sdk.RawLine{
		Source: "journald:keycloak",
		Line:   []byte(line),
		At:     time.Date(2026, 8, 25, 16, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	return evs
}

func TestKeycloakParse_TableDriven(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		line   string
		kind   string
		ip     string
		fields map[string]string
	}{
		{
			name: "login error full line",
			line: "2026-08-25 16:00:00,101 WARN  [org.keycloak.events] (executor-thread-1) type=LOGIN_ERROR, realmId=master, clientId=account, userId=null, ipAddress=203.0.113.160, error=invalid_user_credentials, auth_method=openid-connect, username=admin",
			kind: "keycloak_auth_fail", ip: "203.0.113.160",
			fields: map[string]string{"user": "admin", "realm": "master", "error": "invalid_user_credentials"},
		},
		{
			name: "order-independent attributes (ip after error)",
			line: "type=LOGIN_ERROR, realmId=prod, error=user_not_found, ipAddress=2001:db8::dd, username=user@example.com",
			kind: "keycloak_auth_fail", ip: "2001:db8::dd",
			fields: map[string]string{"user": "user@example.com", "realm": "prod", "error": "user_not_found"},
		},
		{
			name: "username null is omitted",
			line: "type=LOGIN_ERROR, realmId=master, username=null, ipAddress=203.0.113.161, error=invalid_user_credentials",
			kind: "keycloak_auth_fail", ip: "203.0.113.161",
			fields: map[string]string{"realm": "master"},
		},
		{name: "LOGIN success is silent", line: "type=LOGIN, realmId=master, ipAddress=198.51.100.9, username=evert"},
		{name: "CODE_TO_TOKEN is silent", line: "type=CODE_TO_TOKEN, realmId=master, ipAddress=198.51.100.9"},
		{name: "LOGIN_ERROR without ipAddress is dropped", line: "type=LOGIN_ERROR, realmId=master, error=invalid_user_credentials"},
		{name: "invalid ipAddress is dropped", line: "type=LOGIN_ERROR, ipAddress=zz.bad, error=x"},
		{name: "quarkus startup noise", line: "2026-08-25 16:00:10,606 INFO  [io.quarkus] (main) Keycloak 25.0.0 on JVM started"},
		{name: "empty", line: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evs := parseKCLine(t, tc.line)
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
			if tc.name == "username null is omitted" {
				if _, ok := ev.Fields["user"]; ok {
					t.Error("user=null must not become a field")
				}
			}
		})
	}
}

func TestKeycloakParse_Fixtures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file    string
		source  string
		want    int
		wantIPs map[string]int
	}{
		{
			file: "journald.log", source: "journald:keycloak", want: 3,
			wantIPs: map[string]int{"203.0.113.160": 2, "2001:db8::dd": 1},
		},
		{
			file: "docker.log", source: "docker:keycloak-1", want: 1,
			wantIPs: map[string]int{"203.0.113.170": 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "keycloak", tc.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			p := newTestKeycloakParser()
			got := 0
			gotIPs := map[string]int{}
			for _, line := range strings.Split(string(data), "\n") {
				evs, err := p.Parse(sdk.RawLine{Source: tc.source, Line: []byte(line), At: time.Now()})
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				for _, ev := range evs {
					if ev.Kind != "keycloak_auth_fail" {
						t.Errorf("unexpected kind %q", ev.Kind)
					}
					got++
					gotIPs[ev.SourceIP.String()]++
				}
			}
			if got != tc.want {
				t.Errorf("events = %d, want %d (negative fixtures must stay silent)", got, tc.want)
			}
			for ip, n := range tc.wantIPs {
				if gotIPs[ip] != n {
					t.Errorf("ip %s = %d, want %d (all: %v)", ip, gotIPs[ip], n, gotIPs)
				}
			}
		})
	}
}

func TestKeycloakMatches(t *testing.T) {
	t.Parallel()
	yes := []string{
		"keycloak:whatever",
		"journald:keycloak",
		"journald:keycloak.service",
		"docker:keycloak",
		"docker:iam-keycloak-1",
		"file:/var/log/keycloak.log",
		"/var/log/keycloak.log",
	}
	no := []string{
		"journald:keycloak-backup",
		"docker:nginx",
		"nginx:/var/log/keycloak.log",
		"file:/var/log/nginx/access.log",
	}
	p := newTestKeycloakParser()
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

func TestKeycloakParse_CapsAndHostileInput(t *testing.T) {
	t.Parallel()
	huge := "type=LOGIN_ERROR, ipAddress=203.0.113.5, username=" + strings.Repeat("A", maxLineBytes)
	if evs := parseKCLine(t, huge); len(evs) != 0 {
		t.Fatalf("oversized line must be skipped, got %+v", evs)
	}
	line := "type=LOGIN_ERROR, ipAddress=203.0.113.5, username=" + strings.Repeat("u", 500) + ", error=x"
	evs := parseKCLine(t, line)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	if got := len(evs[0].Fields["user"]); got != maxKeycloakUserBytes {
		t.Errorf("user length = %d, want capped at %d", got, maxKeycloakUserBytes)
	}
	for _, hostile := range []string{
		"\x1b[31mtype=LOGIN_ERROR, ipAddress=203.0.113.5\x1b[0m, error=x",
		"type=LOGIN_ERROR, ipAddress=203.0.113.5,\r\nINJECTED",
		string([]byte{0x00, 0xff, 0xfe}),
	} {
		_ = parseKCLine(t, hostile)
	}
}
