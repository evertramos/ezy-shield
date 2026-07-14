package parser_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// fuzzDiscardLogger returns a logger that discards all output, used in fuzz tests
// to avoid flooding stdout.
func fuzzDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// FuzzSSHParser ensures the parser never panics on arbitrary input.
func FuzzSSHParser(f *testing.F) {
	// Seed corpus: representative real and pathological inputs.
	f.Add([]byte("Jan 15 10:00:01 webserver sshd[12345]: Failed password for root from 192.0.2.1 port 40122 ssh2"))
	f.Add([]byte("Invalid user admin from 192.0.2.2 port 41033"))
	f.Add([]byte("Accepted publickey for deploy from 192.0.2.3 port 52100 ssh2: RSA SHA256:AAAA"))
	f.Add([]byte("Failed password for invalid user testuser from 192.0.2.4 port 33901 ssh2"))
	f.Add([]byte("Failed password for root from 2001:db8::1 port 44210 ssh2"))
	// RFC3339/ISO-8601 syslog prefix + sshd-session (Debian 12+/Ubuntu 24.04+).
	f.Add([]byte("2026-07-13T22:57:35.182105+00:00 host sshd-session[1079310]: Failed password for invalid user root from 192.0.2.8 port 58446 ssh2"))
	f.Add([]byte("2026-07-13T22:58:44+00:00 host sshd-session[1079738]: Invalid user infinity from 192.0.2.9 port 36049"))
	f.Add([]byte("2026-07-13T22:59:11Z host sshd[1079905]: Accepted publickey for testuser from 192.0.2.10 port 2901 ssh2"))
	// Malformed ISO prefix (truncated timestamp) must not panic.
	f.Add([]byte("2026-07-13T99:99 host sshd-session[1]: Failed password for root from 192.0.2.1 port 22 ssh2"))
	// Connection closed by invalid user
	f.Add([]byte("Connection closed by invalid user admin 192.0.2.1 port 32792 [preauth]"))
	// SSH dispatch fatal (invalid user)
	f.Add([]byte("ssh_dispatch_run_fatal: Connection from invalid user testuser 192.0.2.2 port 32846: Software caused connection abort [preauth]"))
	// Banner exchange error (no username)
	f.Add([]byte("banner exchange: Connection from 192.0.2.3 port 50442: invalid format"))
	// ISO-prefixed banner error
	f.Add([]byte("2026-07-13T23:30:36.020302+00:00 host sshd-session[1093238]: banner exchange: Connection from 192.0.2.4 port 50442: invalid format"))
	// Canonical probe patterns (issue #140): bare + authenticating-user + pam + protocol.
	f.Add([]byte("Connection closed by 192.0.2.5 port 60216"))
	f.Add([]byte("Connection reset by 192.0.2.6 port 54990"))
	f.Add([]byte("Received disconnect from 192.0.2.7 port 40780:11: Bye Bye [preauth]"))
	f.Add([]byte("Disconnected from invalid user root 192.0.2.8 port 40780"))
	f.Add([]byte("Connection closed by authenticating user kylian 192.0.2.9 port 40780 [preauth]"))
	f.Add([]byte("Disconnecting invalid user test 192.0.2.10 port 5678: Too many authentication failures"))
	f.Add([]byte("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.11  user=root"))
	f.Add([]byte("PAM 4 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.12  user=root"))
	f.Add([]byte("error: kex_exchange_identification: Connection reset by 192.0.2.13 port 50442"))
	f.Add([]byte("Unable to negotiate with 192.0.2.14 port 5000: no matching host key type found. Their offer: ssh-rsa"))
	f.Add([]byte("error: maximum authentication attempts exceeded for invalid user root from 192.0.2.15 port 2222 ssh2 [preauth]"))
	// No-IP protocol lines (must be skipped cleanly, never panic).
	f.Add([]byte("pam_unix(sshd:auth): check pass; user unknown"))
	f.Add([]byte("error: kex_exchange_identification: read: Connection reset by peer"))
	f.Add([]byte("PAM service(sshd) ignoring max retries; 5 > 3"))
	// Malformed rhost (not an IP) must not create an event or panic.
	f.Add([]byte("pam_unix(sshd:auth): authentication failure; rhost=not-an-ip  user=root"))
	f.Add([]byte(""))
	f.Add([]byte("THIS IS GARBAGE"))
	f.Add([]byte("\x00\x01\x02\x03"))                                                    // binary input
	f.Add([]byte(strings.Repeat("A", 4097)))                                             // oversized
	f.Add([]byte(strings.Repeat("A", 4096)))                                             // exactly at limit
	f.Add([]byte("Failed password for root from [2001:db8::1] port 44210 ssh2"))         // bracketed IPv6
	f.Add([]byte("\x1b[31mFailed password\x1b[0m for root from 192.0.2.1 port 22 ssh2")) // ANSI injection in line
	f.Add([]byte("Failed password for root from \x00192.0.2.1 port 22 ssh2"))            // null byte in IP field
	f.Add([]byte("Failed password for root from 192.0.2.1 port 22 ssh2\r\nINJECTED"))    // CRLF log-line injection
	f.Add([]byte(strings.Repeat("\xff", 64)))                                            // high-byte garbage

	f.Fuzz(func(_ *testing.T, b []byte) {
		p := parser.NewSSHParser(fuzzDiscardLogger())
		line := sdk.RawLine{
			Source: "file:/var/log/auth.log",
			Line:   b,
			At:     time.Now(),
		}
		// Must not panic.
		_, _ = p.Parse(line)
	})
}
