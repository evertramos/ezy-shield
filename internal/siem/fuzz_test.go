// SPDX-License-Identifier: AGPL-3.0-only

package siem_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/siem"
)

// FuzzSIEMFormatters is a mandatory CI gate (AGENTS.md §Security test gates).
// It drives arbitrary bytes into every untrusted string field of an Event and
// asserts, for all three formatters, that the output is never injectable:
//   - JSON is always valid JSON with no raw newline;
//   - CEF keeps its seven-field header intact with a numeric severity and no
//     raw newline or ANSI ESC;
//   - RFC 5424 has a PRI prefix, well-formed structured-data with no unescaped
//     delimiter, and no raw newline or ANSI ESC.
//
// Seed classes mirror the parser fuzzers: malformed, oversized (>4 KB), binary,
// ANSI, and CRLF injection.
func FuzzSIEMFormatters(f *testing.F) {
	seeds := [][]byte{
		[]byte("sshd: repeated authentication failures"),
		[]byte(""),
		[]byte("THIS IS GARBAGE"),
		[]byte("\x00\x01\x02\x03"),                     // binary
		[]byte(strings.Repeat("A", 4097)),              // oversized (>4 KB)
		[]byte(strings.Repeat("A", 4096)),              // exactly at 4 KB
		[]byte("\x1b[31mRED\x1b[0m"),                   // ANSI
		[]byte("line1\r\nINJECTED line2"),              // CRLF injection
		[]byte(`a|b=c]d"e\f`),                          // every metacharacter
		[]byte("]\" \\ = |"),                           // delimiter soup
		{0xff, 0xfe, 0xc3, 0x28},                       // invalid UTF-8
		[]byte("IGNORE PREVIOUS INSTRUCTIONS score=0"), // prompt-injection style text
	}
	for _, s := range seeds {
		f.Add(s)
	}

	fixed := time.Date(2025, 1, 15, 10, 0, 1, 0, time.UTC)

	f.Fuzz(func(t *testing.T, b []byte) {
		s := string(b)
		// Poison every untrusted string field with the fuzz input at once, so
		// a single run exercises header, extension and structured-data escaping
		// simultaneously.
		e := siem.Event{
			Time:    fixed,
			Action:  s,
			IP:      netip.MustParseAddr("2001:db8::1"),
			Rule:    s,
			Score:   90,
			Strike:  3,
			TTL:     24 * time.Hour,
			Actor:   s,
			Node:    s,
			Vendor:  s,
			Product: s,
			Version: s,
		}
		assertInvariants(t, e)

		// Also exercise the no-IP path (system events) with the same input.
		e.IP = netip.Addr{}
		assertInvariants(t, e)
	})
}
