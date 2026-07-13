package parser_test

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// goldenEvent is the shape of each record in a *.golden.json fixture file.
type goldenEvent struct {
	Kind     string            `json:"kind"`
	SourceIP string            `json:"source_ip"`
	Fields   map[string]string `json:"fields"`
}

// discardLogger returns a slog.Logger that discards all output. Using
// io.Discard avoids the fd-0 finalizer trap of os.NewFile(0, os.DevNull),
// which would close stdin when the *os.File was GC'd and cause spurious
// EBADF errors in unrelated tests opening fixture files.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// runGoldenTest parses every line in fixtureFile and compares the resulting
// events against the expected events in goldenFile.
func runGoldenTest(t *testing.T, fixtureFile, goldenFile, origin string) {
	t.Helper()

	p := parser.NewSSHParser(discardLogger())

	f, err := os.Open(fixtureFile) //nolint:gosec // fixtureFile is a test-controlled constant path, not attacker-controlled
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close() //nolint:errcheck

	var got []sdk.Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		evs, err := p.Parse(sdk.RawLine{
			Source: origin,
			Line:   []byte(line),
			At:     time.Now(),
		})
		if err != nil {
			t.Errorf("Parse(%q) returned error: %v", line, err)
			continue
		}
		got = append(got, evs...)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan fixture: %v", err)
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

// TestSSHParser_GoldenAuthLog tests parsing of full syslog-format lines.
func TestSSHParser_GoldenAuthLog(t *testing.T) {
	runGoldenTest(t,
		"../../fixtures/ssh/auth.log",
		"../../fixtures/ssh/auth.log.golden.json",
		"file:/var/log/auth.log",
	)
}

// TestSSHParser_GoldenJournald tests parsing of journald (message-only) format lines.
func TestSSHParser_GoldenJournald(t *testing.T) {
	runGoldenTest(t,
		"../../fixtures/ssh/journald.log",
		"../../fixtures/ssh/journald.log.golden.json",
		"journald:sshd",
	)
}

// TestSSHParser_Matches verifies the Matches predicate.
func TestSSHParser_Matches(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())

	cases := []struct {
		source string
		want   bool
	}{
		{"journald:sshd", true},
		{"journald:sshd-session", true}, // OpenSSH 8.9+ with systemd session tracking
		{"file:/var/log/auth.log", true},
		{"file:/var/log/secure", true},
		{"file:/etc/auth.log", true},
		{"ssh:my-sshd-container", true}, // docker collector with parser: ssh
		{"ssh:/custom/auth.log", true},  // file collector with parser: ssh
		{"file:/var/log/nginx/access.log", false},
		{"journald:nginx", false},
		{"nginx:mycontainer", false},
		{"", false},
	}
	for _, tc := range cases {
		got := p.Matches(tc.source)
		if got != tc.want {
			t.Errorf("Matches(%q) = %v, want %v", tc.source, got, tc.want)
		}
	}
}

// TestSSHParser_EdgeCases covers table-driven edge case inputs.
func TestSSHParser_EdgeCases(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())

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
			name:      "junk line",
			line:      []byte("THIS IS NOT A VALID LOG LINE"),
			wantCount: 0,
		},
		{
			name:      "valid IPv4 fail",
			line:      []byte("Failed password for root from 192.0.2.1 port 40122 ssh2"),
			wantCount: 1,
		},
		{
			name:      "valid IPv6 fail",
			line:      []byte("Failed password for root from 2001:db8::1 port 44210 ssh2"),
			wantCount: 1,
		},
		{
			// Some older sshd versions log IPv6 with brackets, e.g. [2001:db8::1].
			// The current regex does not match brackets in the IP capture group,
			// so this line is skipped gracefully (no crash, no event).
			name:      "IPv6 with brackets",
			line:      []byte("Failed password for root from [2001:db8::1] port 44210 ssh2"),
			wantCount: 0,
		},
		{
			// Username with control characters — the spec says IP should still be
			// parsed if possible but username safely handled. \x00 and \x1b ARE
			// matched by \S in Go's regexp (they are non-whitespace), so the regex
			// captures them as part of the username. The line produces one event;
			// the username is truncated at maxUsernameBytes but otherwise passed
			// through. A separate test validates the username cap.
			name:      "username with control chars",
			line:      []byte("Failed password for \x00\x1badmin from 192.0.2.1 port 40122 ssh2"),
			wantCount: 1,
		},
		{
			name:      "failed invalid user syslog",
			line:      []byte("Jan 15 10:00:04 webserver sshd[12348]: Failed password for invalid user testuser from 192.0.2.4 port 33901 ssh2"),
			wantCount: 1,
		},
		{
			name:      "not allowed AllowUsers",
			line:      []byte("User root from 192.0.2.5 not allowed because not listed in AllowUsers"),
			wantCount: 1,
		},
		{
			name:      "not allowed DenyUsers",
			line:      []byte("User admin from 192.0.2.6 not allowed because listed in DenyUsers"),
			wantCount: 1,
		},
		{
			name:      "sshd-session syslog prefix",
			line:      []byte("Jan 15 10:00:05 webserver sshd-session[12349]: Failed password for root from 192.0.2.7 port 40123 ssh2"),
			wantCount: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := p.Parse(sdk.RawLine{
				Source: "file:/var/log/auth.log",
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

// TestSSHParser_FailedInvalidUserKind ensures lines with "for invalid user" produce
// ssh_invalid_user (not ssh_fail) and that more-specific pattern wins.
func TestSSHParser_FailedInvalidUserKind(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())

	line := sdk.RawLine{
		Source: "journald:sshd",
		Line:   []byte("Failed password for invalid user testuser from 192.0.2.4 port 33901 ssh2"),
		At:     time.Now(),
	}
	evs, err := p.Parse(line)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0].Kind != "ssh_invalid_user" {
		t.Errorf("kind: got %q, want %q", evs[0].Kind, "ssh_invalid_user")
	}
	if evs[0].Fields["username"] != "testuser" {
		t.Errorf("username: got %q, want %q", evs[0].Fields["username"], "testuser")
	}
}

// TestSSHParser_NotAllowedKind ensures "not allowed" lines produce ssh_invalid_user.
func TestSSHParser_NotAllowedKind(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())

	line := sdk.RawLine{
		Source: "journald:sshd-session",
		Line:   []byte("User root from 192.0.2.5 not allowed because not listed in AllowUsers"),
		At:     time.Now(),
	}
	evs, err := p.Parse(line)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0].Kind != "ssh_invalid_user" {
		t.Errorf("kind: got %q, want %q", evs[0].Kind, "ssh_invalid_user")
	}
	if evs[0].Fields["username"] != "root" {
		t.Errorf("username: got %q, want %q", evs[0].Fields["username"], "root")
	}
	if evs[0].SourceIP.String() != "192.0.2.5" {
		t.Errorf("source_ip: got %q, want %q", evs[0].SourceIP.String(), "192.0.2.5")
	}
}

// TestSSHParser_SyslogTimestamp verifies that the syslog timestamp is parsed and
// returned as the event Time (within the same second).
func TestSSHParser_SyslogTimestamp(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())

	now := time.Now()
	line := sdk.RawLine{
		Source: "file:/var/log/auth.log",
		Line:   []byte("Jan 15 10:00:01 webserver sshd[12345]: Failed password for root from 192.0.2.1 port 40122 ssh2"),
		At:     now,
	}
	evs, err := p.Parse(line)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	// The event time should be Jan 15 10:00:01 in current year, not line.At.
	ev := evs[0]
	if ev.Time.Month() != 1 || ev.Time.Day() != 15 ||
		ev.Time.Hour() != 10 || ev.Time.Minute() != 0 || ev.Time.Second() != 1 {
		t.Errorf("unexpected event time: %v", ev.Time)
	}
}
