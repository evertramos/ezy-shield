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
