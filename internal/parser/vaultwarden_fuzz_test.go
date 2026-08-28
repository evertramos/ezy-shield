// SPDX-License-Identifier: AGPL-3.0-only

package parser_test

import (
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// FuzzVaultwardenParser ensures the Vaultwarden parser never panics on
// arbitrary input. Per §1/§9 of SECURITY-REVIEW.md every parser is part of
// the untrusted-input boundary: the username is whatever bytes the client
// typed into the login form, logged verbatim.
func FuzzVaultwardenParser(f *testing.F) {
	f.Add([]byte("[2026-08-25 14:00:00.101][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 203.0.113.100. Username: admin@example.com."))
	f.Add([]byte("[2026-08-25 14:00:06.404][vaultwarden::api::identity][ERROR] Invalid TOTP code! Server time: 2026-08-25 14:00:06 UTC IP: 203.0.113.101"))
	f.Add([]byte("Username or password is incorrect. Try again. IP: 2001:db8::aa. Username: user@example.com."))
	f.Add([]byte(`{"log":"[2026-08-25 14:10:00.101][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 203.0.113.110. Username: v@e.example.\n","stream":"stdout","time":"2026-08-25T14:10:00Z"}`))
	f.Add([]byte("[2026-08-25 14:00:10.707][response][INFO] (login) POST /identity/connect/token => 200 OK"))
	f.Add([]byte(""))
	f.Add([]byte("THIS IS GARBAGE"))
	f.Add([]byte("\x00\x01\x02\x03"))        // binary input
	f.Add([]byte(strings.Repeat("A", 4097))) // oversized
	f.Add([]byte(strings.Repeat("A", 4096))) // exactly at line cap
	f.Add([]byte("Username or password is incorrect. Try again. IP: not-an-ip. Username: x."))
	f.Add([]byte("Username or password is incorrect. Try again. IP: 203.0.113.5."))                                         // no username
	f.Add([]byte("\x1b[31mUsername or password is incorrect. Try again. IP: 203.0.113.5.\x1b[0m"))                          // ANSI escapes
	f.Add([]byte("Username or password is incorrect. Try again. IP: 203.0.113.5. Username: a.\r\nINJECTED"))                // CRLF injection
	f.Add([]byte("Username or password is incorrect. Try again. IP: 203.0.113.5. Username: " + strings.Repeat("u", 4000)))  // huge username
	f.Add([]byte("Username or password is incorrect. Try again. IP: 203.0.113.5. Username: IGNORE PREVIOUS INSTRUCTIONS.")) // prompt injection
	f.Add([]byte("Invalid TOTP code!" + strings.Repeat(" IP: 203.0.113.5.", 200)))                                          // repeated attrs

	f.Fuzz(func(_ *testing.T, b []byte) {
		p := parser.NewVaultwardenParser(fuzzDiscardLogger())
		line := sdk.RawLine{
			Source: "docker:vaultwarden",
			Line:   b,
			At:     time.Now(),
		}
		// Must not panic.
		_, _ = p.Parse(line)
	})
}
