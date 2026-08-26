// SPDX-License-Identifier: AGPL-3.0-only

package parser_test

import (
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// FuzzDovecotParser ensures the Dovecot login parser never panics on
// arbitrary input. Per §1/§9 of SECURITY-REVIEW.md every parser is part of
// the untrusted-input boundary: IMAP/POP3 clients control the username and
// method strings that end up verbatim in these lines.
func FuzzDovecotParser(f *testing.F) {
	// Seed corpus: representative real and pathological inputs.
	f.Add([]byte("Aug 25 13:00:02 mail dovecot: imap-login: Aborted login (auth failed, 3 attempts in 6 secs): user=<admin>, method=PLAIN, rip=203.0.113.70, lip=198.51.100.1, TLS, session=<x1>"))
	f.Add([]byte("dovecot: pop3-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<root>, method=PLAIN, rip=203.0.113.71"))
	f.Add([]byte("dovecot: imap-login: Disconnected (no auth attempts in 5 secs): rip=203.0.113.72, lip=198.51.100.1, TLS handshaking"))
	f.Add([]byte("dovecot: imap-login: Aborted login (auth failed, 5 attempts in 11 secs): user=<info>, method=LOGIN, rip=2001:db8::71"))
	f.Add([]byte("dovecot: imap-login: Login: user=<evert>, method=PLAIN, rip=198.51.100.9"))
	f.Add([]byte(`{"log":"dovecot: imap-login: Aborted login (auth failed, 2 attempts in 4 secs): user=<p>, method=PLAIN, rip=203.0.113.80\n","stream":"stdout","time":"2026-08-25T13:10:02Z"}`))
	f.Add([]byte(""))
	f.Add([]byte("THIS IS GARBAGE"))
	f.Add([]byte("\x00\x01\x02\x03"))        // binary input
	f.Add([]byte(strings.Repeat("A", 4097))) // oversized
	f.Add([]byte(strings.Repeat("A", 4096))) // exactly at line cap
	f.Add([]byte("dovecot: imap-login: Aborted login (auth failed, 1 attempts in 1 secs): rip=not-an-ip"))
	f.Add([]byte("dovecot: imap-login: Aborted login (auth failed, 1 attempts in 1 secs): lip=198.51.100.1"))                                                    // rip missing
	f.Add([]byte("dovecot: imap-login: Aborted login (auth failed, 999999999999999999999 attempts in 1 secs): rip=203.0.113.5"))                                 // huge count
	f.Add([]byte("dovecot: \x1b[31mimap-login\x1b[0m: Aborted login (auth failed, 1 attempts in 1 secs): rip=203.0.113.5"))                                      // ANSI escapes
	f.Add([]byte("dovecot: imap-login: Aborted login (auth failed, 1 attempts in 1 secs): rip=203.0.113.5\r\nINJECTED"))                                         // CRLF injection
	f.Add([]byte("dovecot: imap-login: Aborted login (auth failed, 1 attempts in 1 secs): user=<" + strings.Repeat("u", 4000) + ">, rip=203.0.113.5"))           // huge username
	f.Add([]byte("dovecot: imap-login: Aborted login (auth failed, 1 attempts in 1 secs): user=<a>, method=" + strings.Repeat("M", 4000) + ", rip=203.0.113.5")) // huge method
	f.Add([]byte("dovecot: imap-login: Aborted login (auth failed, 1 attempts in 1 secs): user=<IGNORE PREVIOUS INSTRUCTIONS>, rip=203.0.113.5"))                // prompt injection
	f.Add([]byte("dovecot: imap-login: Disconnected (no auth attempts" + strings.Repeat("(", 500) + "): rip=203.0.113.5"))                                       // pathological parens

	f.Fuzz(func(_ *testing.T, b []byte) {
		p := parser.NewDovecotParser(fuzzDiscardLogger())
		line := sdk.RawLine{
			Source: "journald:dovecot",
			Line:   b,
			At:     time.Now(),
		}
		// Must not panic.
		_, _ = p.Parse(line)
	})
}
