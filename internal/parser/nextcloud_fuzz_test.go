// SPDX-License-Identifier: AGPL-3.0-only

package parser_test

import (
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// FuzzNextcloudParser ensures the Nextcloud JSON parser never panics on
// arbitrary input. Per §1/§9 of SECURITY-REVIEW.md every parser is part of
// the untrusted-input boundary: the username is form input, and the JSON
// itself can be truncated, deeply nested, or hostile.
func FuzzNextcloudParser(f *testing.F) {
	f.Add([]byte(`{"reqId":"a","level":2,"time":"2026-08-25T15:00:00+00:00","remoteAddr":"203.0.113.130","user":"--","app":"core","method":"POST","url":"/login","message":"Login failed: 'admin' (Remote IP: '203.0.113.130')","userAgent":"UA","version":"29.0.0"}`))
	f.Add([]byte(`{"remoteAddr":"203.0.113.131","app":"admin_audit","message":"Login attempt failed for user: guest"}`))
	f.Add([]byte(`{"remoteAddr":"198.51.100.9","app":"core","message":"Login successful: 'evert'"}`))
	f.Add([]byte(`{"log":"{\"remoteAddr\":\"203.0.113.140\",\"app\":\"core\",\"message\":\"Login failed: 'x'\"}\n","stream":"stdout","time":"2026-08-25T15:10:00Z"}`))
	f.Add([]byte(""))
	f.Add([]byte("not json"))
	f.Add([]byte("{"))
	f.Add([]byte(`{"remoteAddr":"203.0.113.5","app":"core","mess`)) // truncated JSON
	f.Add([]byte("\x00\x01\x02\x03"))                               // binary input
	f.Add([]byte(strings.Repeat("A", 4097)))                        // oversized
	f.Add([]byte(`{"remoteAddr":"not-an-ip","app":"core","message":"Login failed: 'x'"}`))
	f.Add([]byte(`{"remoteAddr":"203.0.113.5","app":"core","message":"Login failed: '` + strings.Repeat("u", 4000) + `'"}`))                                           // huge username
	f.Add([]byte(`{"remoteAddr":"203.0.113.5","app":"core","message":"Login failed: 'x'","x":` + strings.Repeat(`{"a":`, 500) + `1` + strings.Repeat(`}`, 500) + `}`)) // deeply nested
	f.Add([]byte("{\"remoteAddr\":\"203.0.113.5\",\"app\":\"core\",\"message\":\"Login failed: '\x1b[31mANSI\x1b[0m'\"}"))                                             // ANSI in username
	f.Add([]byte(`{"remoteAddr":"203.0.113.5","app":"core","message":"Login failed: 'IGNORE PREVIOUS INSTRUCTIONS'"}`))                                                // prompt injection
	f.Add([]byte(`{"app":"core","message":"Login failed: 'x'"}`))                                                                                                      // remoteAddr missing

	f.Fuzz(func(_ *testing.T, b []byte) {
		p := parser.NewNextcloudParser(fuzzDiscardLogger())
		line := sdk.RawLine{
			Source: "docker:nextcloud",
			Line:   b,
			At:     time.Now(),
		}
		// Must not panic.
		_, _ = p.Parse(line)
	})
}
