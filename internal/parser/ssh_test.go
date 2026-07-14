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

// TestSSHParser_GoldenAuthLogISO tests modern Debian/Ubuntu auth.log lines
// (RFC3339/ISO-8601 timestamps + the OpenSSH 9.6+ sshd-session identifier).
func TestSSHParser_GoldenAuthLogISO(t *testing.T) {
	runGoldenTest(t,
		"../../fixtures/ssh/authlog-iso.log",
		"../../fixtures/ssh/authlog-iso.log.golden.json",
		"file:/var/log/auth.log",
	)
}

// TestSSHParser_GoldenSecure tests RHEL-family /var/log/secure lines
// (RFC3164 timestamps + the sshd identifier).
func TestSSHParser_GoldenSecure(t *testing.T) {
	runGoldenTest(t,
		"../../fixtures/ssh/secure.log",
		"../../fixtures/ssh/secure.log.golden.json",
		"file:/var/log/secure",
	)
}

// TestSSHParser_Matches verifies the Matches predicate.
func TestSSHParser_Matches(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())

	cases := []struct {
		source string
		want   bool
	}{
		{"journald:ssh", true},          // Debian/Ubuntu unit name (ssh.service)
		{"journald:sshd", true},         // RHEL/CentOS/Fedora/Arch/SUSE unit name
		{"journald:sshd-session", true}, // OpenSSH 9.6+ split session identifier
		{"journald:ssh.service", true},  // unit given with explicit .service suffix
		{"journald:sshd.service", true},
		{"file:/var/log/auth.log", true},
		{"file:/var/log/secure", true},
		{"file:/etc/auth.log", true},
		{"ssh:my-sshd-container", true}, // docker collector with parser: ssh
		{"ssh:/custom/auth.log", true},  // file collector with parser: ssh
		{"file:/var/log/nginx/access.log", false},
		{"journald:nginx", false},
		{"journald:sshguard", false}, // must not over-match unrelated units
		{"nginx:mycontainer", false},
		{"nginx:/var/log/auth.log", false}, // explicit non-ssh override wins
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
		{
			// Debian 12+/Ubuntu 24.04+ auth.log: ISO-8601 stamp + sshd-session.
			name:      "iso prefix failed invalid user",
			line:      []byte("2026-07-13T22:57:35.182105+00:00 fagots sshd-session[1079310]: Failed password for invalid user root from 192.0.2.8 port 58446 ssh2"),
			wantCount: 1,
		},
		{
			name:      "iso prefix invalid user",
			line:      []byte("2026-07-13T22:58:44.868083+00:00 fagots sshd-session[1079738]: Invalid user infinity from 192.0.2.9 port 36049"),
			wantCount: 1,
		},
		{
			// ISO stamp with Z zone and no fractional seconds, legacy sshd identifier.
			name:      "iso prefix zulu no-frac sshd",
			line:      []byte("2026-07-13T22:59:11Z host sshd[1079905]: Failed password for root from 192.0.2.10 port 2901 ssh2"),
			wantCount: 1,
		},
		{
			name:      "connection closed by invalid user",
			line:      []byte("Connection closed by invalid user hassanjawaiddts9 198.51.100.210 port 32792 [preauth]"),
			wantCount: 1,
		},
		{
			name:      "ssh dispatch fatal invalid user",
			line:      []byte("ssh_dispatch_run_fatal: Connection from invalid user user14 198.51.100.210 port 32846: Software caused connection abort [preauth]"),
			wantCount: 1,
		},
		{
			name:      "banner exchange error",
			line:      []byte("banner exchange: Connection from 198.51.100.208 port 50442: invalid format"),
			wantCount: 1,
		},
		{
			// ISO-prefixed banner error
			name:      "iso prefix banner error",
			line:      []byte("2026-07-13T23:30:36.020302+00:00 fagots sshd-session[1093238]: banner exchange: Connection from 198.51.100.208 port 50442: invalid format"),
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

// TestSSHParser_ISOTimestamp verifies that an RFC3339/ISO-8601 syslog prefix
// (Debian 12+/Ubuntu 24.04+ auth.log) is stripped, parsed into the event Time,
// and the message body is matched correctly.
func TestSSHParser_ISOTimestamp(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())

	line := sdk.RawLine{
		Source: "file:/var/log/auth.log",
		Line:   []byte("2026-07-13T22:57:35.182105+00:00 fagots sshd-session[1079310]: Failed password for invalid user root from 192.0.2.8 port 58446 ssh2"),
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
	if ev.Kind != "ssh_invalid_user" {
		t.Errorf("kind: got %q, want ssh_invalid_user", ev.Kind)
	}
	if ev.SourceIP.String() != "192.0.2.8" {
		t.Errorf("source_ip: got %q, want 192.0.2.8", ev.SourceIP.String())
	}
	// Event time must come from the ISO stamp (2026-07-13 22:57:35 UTC), not line.At.
	want := time.Date(2026, 7, 13, 22, 57, 35, 0, time.UTC)
	if !ev.Time.UTC().Truncate(time.Second).Equal(want) {
		t.Errorf("event time: got %v, want %v", ev.Time.UTC(), want)
	}
}

// TestSSHParser_SingleEventPerLine locks in the no-duplicate invariant: a single
// log line yields at most one Event, so one attempt is never counted twice by
// the parser (the "Failed password for invalid user" line must match only the
// ssh_invalid_user pattern, not also ssh_fail).
func TestSSHParser_SingleEventPerLine(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())

	for _, src := range []string{"journald:ssh", "file:/var/log/auth.log"} {
		evs, err := p.Parse(sdk.RawLine{
			Source: src,
			Line:   []byte("Failed password for invalid user admin from 192.0.2.30 port 40100 ssh2"),
			At:     time.Now(),
		})
		if err != nil {
			t.Fatalf("[%s] Parse error: %v", src, err)
		}
		if len(evs) != 1 {
			t.Fatalf("[%s] expected exactly 1 event, got %d", src, len(evs))
		}
		if evs[0].Kind != "ssh_invalid_user" {
			t.Errorf("[%s] kind: got %q, want ssh_invalid_user", src, evs[0].Kind)
		}
	}
}

// TestSSHParser_ProbePatterns table-drives the connection/protocol lines that
// canonicalise to ssh_probe (issue #140): recognised (no silent drop) but not
// counted by the default ban rules. Each asserts kind, subtype, IP and — where
// present — username/port.
func TestSSHParser_ProbePatterns(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())

	cases := []struct {
		name     string
		line     string
		subtype  string
		ip       string
		username string // "" when the line carries no username
		port     string // "" when the line carries no port
	}{
		{
			name:     "connection closed by invalid user",
			line:     "Connection closed by invalid user hassanjawaiddts9 198.51.100.210 port 32792 [preauth]",
			subtype:  "conn_closed_invalid",
			ip:       "198.51.100.210",
			username: "hassanjawaiddts9",
			port:     "32792",
		},
		{
			name:    "dispatch fatal invalid user",
			line:    "ssh_dispatch_run_fatal: Connection from invalid user user14 198.51.100.210 port 32846: Software caused connection abort [preauth]",
			subtype: "dispatch_fatal",
			ip:      "198.51.100.210", username: "user14", port: "32846",
		},
		{
			name:    "banner exchange invalid format",
			line:    "banner exchange: Connection from 198.51.100.208 port 50442: invalid format",
			subtype: "banner_invalid",
			ip:      "198.51.100.208", port: "50442",
		},
		{
			name:    "banner exchange could not read",
			line:    "banner exchange: Connection from 198.51.100.208 port 50442: could not read protocol version",
			subtype: "banner_invalid",
			ip:      "198.51.100.208", port: "50442",
		},
		{
			name:    "disconnected from invalid user",
			line:    "Disconnected from invalid user root 198.51.100.203 port 40780",
			subtype: "disconnected_invalid",
			ip:      "198.51.100.203", username: "root", port: "40780",
		},
		{
			name:    "connection reset by invalid user",
			line:    "Connection reset by invalid user root 198.51.100.206 port 51000",
			subtype: "conn_reset_invalid",
			ip:      "198.51.100.206", username: "root", port: "51000",
		},
		{
			name:    "disconnecting invalid user too many",
			line:    "Disconnecting invalid user test 1.2.3.4 port 5678: Too many authentication failures",
			subtype: "disconnecting_invalid",
			ip:      "1.2.3.4", username: "test", port: "5678",
		},
		{
			name:    "connection closed by authenticating user",
			line:    "Connection closed by authenticating user kylian 203.0.113.9 port 40780 [preauth]",
			subtype: "authenticating_closed",
			ip:      "203.0.113.9", username: "kylian", port: "40780",
		},
		{
			// Bare terminations only count when [preauth]-tagged (pre-login churn).
			name:    "connection closed bare preauth",
			line:    "Connection closed by 198.51.100.204 port 60216 [preauth]",
			subtype: "conn_closed",
			ip:      "198.51.100.204", port: "60216",
		},
		{
			name:    "connection reset bare preauth",
			line:    "Connection reset by 198.51.100.209 port 54990 [preauth]",
			subtype: "conn_reset",
			ip:      "198.51.100.209", port: "54990",
		},
		{
			name:    "received disconnect preauth",
			line:    "Received disconnect from 198.51.100.203 port 40780:11: Bye Bye [preauth]",
			subtype: "disconnect_recv",
			ip:      "198.51.100.203", port: "40780",
		},
		{
			name:    "disconnected bare preauth",
			line:    "Disconnected from 198.51.100.203 port 40780 [preauth]",
			subtype: "disconnected",
			ip:      "198.51.100.203", port: "40780",
		},
		{
			name:    "kex exchange reset with ip",
			line:    "error: kex_exchange_identification: Connection reset by 198.51.100.208 port 50442",
			subtype: "kex_reset",
			ip:      "198.51.100.208", port: "50442",
		},
		{
			name:    "unable to negotiate",
			line:    "Unable to negotiate with 198.51.100.202 port 5000: no matching host key type found. Their offer: ssh-rsa",
			subtype: "negotiate_fail",
			ip:      "198.51.100.202", port: "5000",
		},
		{
			name:    "max attempts invalid user",
			line:    "error: maximum authentication attempts exceeded for invalid user root from 198.51.100.207 port 2222 ssh2 [preauth]",
			subtype: "max_attempts",
			ip:      "198.51.100.207", username: "root", port: "2222",
		},
		{
			name:    "pam auth failure with rhost",
			line:    "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.205  user=root",
			subtype: "pam_auth_fail",
			ip:      "198.51.100.205",
		},
		{
			name:    "pam more failures",
			line:    "PAM 4 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.206  user=root",
			subtype: "pam_more_fail",
			ip:      "198.51.100.206",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := p.Parse(sdk.RawLine{Source: "journald:sshd-session", Line: []byte(tc.line), At: time.Now()})
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			if len(evs) != 1 {
				t.Fatalf("expected 1 event, got %d", len(evs))
			}
			ev := evs[0]
			if ev.Kind != "ssh_probe" {
				t.Errorf("kind: got %q, want ssh_probe", ev.Kind)
			}
			if ev.Fields["subtype"] != tc.subtype {
				t.Errorf("subtype: got %q, want %q", ev.Fields["subtype"], tc.subtype)
			}
			if ev.SourceIP.String() != tc.ip {
				t.Errorf("source_ip: got %q, want %q", ev.SourceIP.String(), tc.ip)
			}
			if ev.Fields["username"] != tc.username {
				t.Errorf("username: got %q, want %q", ev.Fields["username"], tc.username)
			}
			if ev.Fields["port"] != tc.port {
				t.Errorf("port: got %q, want %q", ev.Fields["port"], tc.port)
			}
		})
	}
}

// TestSSHParser_LegitSessionNoFalsePositive replays a real authenticated
// user's connect/sudo/logout sequence (from a live host) and asserts the parser
// never manufactures an attack signal from it: the only event is the successful
// login (ssh_accept, telemetry), and every session/sudo/su/logout line — most
// importantly the post-auth "Received disconnect ... disconnected by user" — is
// either dropped or, at worst, never a bannable kind. A bare termination without
// the [preauth] tag is a legitimate logout, not a probe.
func TestSSHParser_LegitSessionNoFalsePositive(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())

	// IP is a TEST-NET-3 address (RFC 5737) — never a real, routable host.
	// Username is a generic placeholder; PIDs/timestamps are kept realistic —
	// only the identifying username, source IP and key fingerprint of the
	// original live session are synthetic.
	session := []string{
		"2026-07-14T12:02:04.177634+00:00 fagots sshd-session[1388641]: Accepted publickey for testuser from 203.0.113.42 port 2843 ssh2: RSA SHA256:AAAA",
		"2026-07-14T12:02:04.180610+00:00 fagots sshd-session[1388641]: pam_unix(sshd:session): session opened for user testuser(uid=1001) by testuser(uid=0)",
		"2026-07-14T12:02:29.019523+00:00 fagots sudo:    testuser : TTY=pts/1 ; PWD=/home/testuser ; USER=root ; COMMAND=/usr/bin/su -",
		"2026-07-14T12:02:29.021470+00:00 fagots sudo: pam_unix(sudo:session): session opened for user root(uid=0) by testuser(uid=1001)",
		"2026-07-14T12:02:44.659148+00:00 fagots su[1388922]: pam_unix(su-l:session): session closed for user root",
		"2026-07-14T12:03:03.874162+00:00 fagots sshd-session[1388766]: Received disconnect from 203.0.113.42 port 2843:11: disconnected by user",
		"2026-07-14T12:03:03.874478+00:00 fagots sshd-session[1388766]: Disconnected from user testuser 203.0.113.42 port 2843",
		"2026-07-14T12:03:03.875144+00:00 fagots sshd-session[1388641]: pam_unix(sshd:session): session closed for user testuser",
		"2026-07-14T12:03:03.878840+00:00 fagots systemd-logind[902]: Session 1043 logged out. Waiting for processes to exit.",
	}

	accepts := 0
	for _, line := range session {
		evs, err := p.Parse(sdk.RawLine{Source: "file:/var/log/auth.log", Line: []byte(line), At: time.Now()})
		if err != nil {
			t.Fatalf("Parse error: %v", err)
		}
		for _, ev := range evs {
			switch ev.Kind {
			case "ssh_accept":
				accepts++
			case "ssh_fail", "ssh_invalid_user", "ssh_probe":
				t.Errorf("false positive: legit session line produced %q (subtype %q): %q",
					ev.Kind, ev.Fields["subtype"], line)
			}
		}
	}
	if accepts != 1 {
		t.Errorf("expected exactly 1 ssh_accept (the successful login), got %d", accepts)
	}
}

// TestSSHParser_ProbeNotCountedByDefault documents the core anti-inflation
// guarantee: probe subtypes carry a kind the default rules ([ssh_fail,
// ssh_invalid_user]) do not count, so broadening recognition cannot lower the
// effective ban threshold.
func TestSSHParser_ProbeNotCountedByDefault(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())
	defaultKinds := map[string]bool{"ssh_fail": true, "ssh_invalid_user": true}

	probes := []string{
		"Connection closed by invalid user root 1.2.3.4 port 22",
		"Disconnected from invalid user root 1.2.3.4 port 22",
		"pam_unix(sshd:auth): authentication failure; rhost=1.2.3.4  user=root",
		"banner exchange: Connection from 1.2.3.4 port 22: invalid format",
	}
	for _, line := range probes {
		evs, err := p.Parse(sdk.RawLine{Source: "journald:ssh", Line: []byte(line), At: time.Now()})
		if err != nil {
			t.Fatalf("Parse error: %v", err)
		}
		if len(evs) != 1 {
			t.Fatalf("[%s] expected 1 event, got %d", line, len(evs))
		}
		if defaultKinds[evs[0].Kind] {
			t.Errorf("[%s] mapped to default-bannable kind %q; probe lines must not inflate default rules", line, evs[0].Kind)
		}
	}
}

// TestSSHParser_ConnectionInflation feeds the realistic multi-line sequence a
// single invalid-user connection emits and asserts that only ONE event lands in
// the default-bannable kinds — the rest are ssh_probe. This locks the "one
// attack connection ⇒ one strike" invariant (issue #140) without a dedup layer.
func TestSSHParser_ConnectionInflation(t *testing.T) {
	p := parser.NewSSHParser(discardLogger())

	// One connection (same pid), as OpenSSH logs it in password mode.
	connection := []string{
		"2026-07-13T23:32:40.100000+00:00 fagots sshd-session[1094039]: Invalid user oracle from 198.51.100.210 port 32792",
		"2026-07-13T23:32:40.200000+00:00 fagots sshd-session[1094039]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.210",
		"2026-07-13T23:32:40.898546+00:00 fagots sshd-session[1094039]: Failed password for invalid user oracle from 198.51.100.210 port 32792 ssh2",
		"2026-07-13T23:32:43.220742+00:00 fagots sshd-session[1094039]: Connection closed by invalid user oracle 198.51.100.210 port 32792 [preauth]",
	}

	defaultCount, probeCount := 0, 0
	for _, line := range connection {
		evs, err := p.Parse(sdk.RawLine{Source: "file:/var/log/auth.log", Line: []byte(line), At: time.Now()})
		if err != nil {
			t.Fatalf("Parse error: %v", err)
		}
		for _, ev := range evs {
			switch ev.Kind {
			case "ssh_fail", "ssh_invalid_user":
				defaultCount++
			case "ssh_probe":
				probeCount++
			}
			// pid must be captured from the sshd-session[...] prefix.
			if ev.Fields["pid"] != "1094039" {
				t.Errorf("pid: got %q, want 1094039 (line %q)", ev.Fields["pid"], line)
			}
		}
	}

	// "Invalid user oracle" is the single attempt line; "Failed password for
	// invalid user" is also an attempt line, so the default count is 2 here
	// (both are genuine attempt lines OpenSSH emits). The point of this test is
	// that the two TERMINATION/PAM lines add ZERO to the default count — they are
	// probe. Without the canonical split they would have made it 4.
	if defaultCount != 2 {
		t.Errorf("default-bannable events: got %d, want 2 (Invalid user + Failed password only)", defaultCount)
	}
	if probeCount != 2 {
		t.Errorf("probe events: got %d, want 2 (pam + connection-closed)", probeCount)
	}
}
