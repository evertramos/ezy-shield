// SPDX-License-Identifier: AGPL-3.0-only

package parser_test

import (
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// FuzzKeycloakParser ensures the Keycloak event parser never panics on
// arbitrary input. Per §1/§9 of SECURITY-REVIEW.md every parser is part of
// the untrusted-input boundary: username and realm attributes carry
// client-typed bytes verbatim.
func FuzzKeycloakParser(f *testing.F) {
	f.Add([]byte("2026-08-25 16:00:00,101 WARN  [org.keycloak.events] (executor-thread-1) type=LOGIN_ERROR, realmId=master, clientId=account, userId=null, ipAddress=203.0.113.160, error=invalid_user_credentials, username=admin"))
	f.Add([]byte("type=LOGIN_ERROR, error=user_not_found, ipAddress=2001:db8::dd, username=u@e.example"))
	f.Add([]byte("type=LOGIN, realmId=master, ipAddress=198.51.100.9, username=evert"))
	f.Add([]byte("type=CODE_TO_TOKEN, realmId=master, ipAddress=198.51.100.9"))
	f.Add([]byte(`{"log":"type=LOGIN_ERROR, realmId=master, ipAddress=203.0.113.170, error=invalid_user_credentials, username=admin\n","stream":"stdout","time":"2026-08-25T16:10:00Z"}`))
	f.Add([]byte(""))
	f.Add([]byte("THIS IS GARBAGE"))
	f.Add([]byte("\x00\x01\x02\x03"))        // binary input
	f.Add([]byte(strings.Repeat("A", 4097))) // oversized
	f.Add([]byte(strings.Repeat("A", 4096))) // exactly at line cap
	f.Add([]byte("type=LOGIN_ERROR, ipAddress=not-an-ip, error=x"))
	f.Add([]byte("type=LOGIN_ERROR, error=x"))                                                      // no address
	f.Add([]byte("\x1b[31mtype=LOGIN_ERROR, ipAddress=203.0.113.5\x1b[0m"))                         // ANSI escapes
	f.Add([]byte("type=LOGIN_ERROR, ipAddress=203.0.113.5,\r\nINJECTED type=LOGIN_ERROR"))          // CRLF injection
	f.Add([]byte("type=LOGIN_ERROR, ipAddress=203.0.113.5, username=" + strings.Repeat("u", 4000))) // huge username
	f.Add([]byte("type=LOGIN_ERROR, ipAddress=203.0.113.5, username=IGNORE_PREVIOUS_INSTRUCTIONS")) // prompt injection
	f.Add([]byte("type=LOGIN_ERROR," + strings.Repeat(" ipAddress=203.0.113.5,", 300)))             // repeated attrs
	f.Add([]byte(strings.Repeat("type=LOGIN_ERROR, ", 200) + "ipAddress=203.0.113.5"))              // repeated gate token

	f.Fuzz(func(_ *testing.T, b []byte) {
		p := parser.NewKeycloakParser(fuzzDiscardLogger())
		line := sdk.RawLine{
			Source: "journald:keycloak",
			Line:   b,
			At:     time.Now(),
		}
		// Must not panic.
		_, _ = p.Parse(line)
	})
}
