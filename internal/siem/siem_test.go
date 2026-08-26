// SPDX-License-Identifier: AGPL-3.0-only

package siem_test

import (
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/siem"
)

// update regenerates the golden files instead of comparing against them:
//
//	go test ./internal/siem -run TestFormatters_Golden -update
//
// Regenerated goldens MUST be inspected by hand before committing — the point
// of this issue is that the escaping is correct, so a blindly-updated golden
// proves nothing.
var update = flag.Bool("update", false, "update SIEM golden files")

// fixedTime is a constant event time so golden output is deterministic.
var fixedTime = time.Date(2025, 1, 15, 10, 0, 1, 0, time.UTC)

// baseEvent is a normal ban event; hostile cases copy it and poison one or
// more string fields so the golden isolates each escaping path.
func baseEvent() siem.Event {
	return siem.Event{
		Time:    fixedTime,
		Action:  "ban",
		IP:      netip.MustParseAddr("198.51.100.23"),
		Rule:    "sshd: repeated auth failures",
		Score:   90,
		Strike:  3,
		TTL:     24 * time.Hour,
		Actor:   "rules",
		Node:    "edge-01",
		Vendor:  "ezy",
		Product: "EzyShield",
		Version: "1.4.2",
	}
}

// withRule returns baseEvent with Rule replaced by the (hostile) value.
func withRule(rule string) siem.Event {
	e := baseEvent()
	e.Rule = rule
	return e
}

// formatterCase pairs a golden-file name with the event that produces it.
type formatterCase struct {
	name  string
	event siem.Event
}

func formatterCases() []formatterCase {
	// A field poisoned with every metacharacter at once, plus a newline and
	// an ANSI sequence, reused across Rule/Actor/Node in the "multi" case.
	poison := "a|b=c]d\"e\\f\ng\x1b[31mh"
	return []formatterCase{
		{"clean", baseEvent()},
		{"pipe", withRule("nginx|scanner|probe")},
		{"equals", withRule("path=/x cmd=inject")},
		{"bracket", withRule(`end] SD-INJECT="x`)},
		{"quote", withRule(`he said "run this"`)},
		{"newline", withRule("line1\nline2\r\nDROP TABLE")},
		{"ansi", withRule("\x1b[31mALERT\x1b[0m reset")},
		{"garbage4k", withRule(strings.Repeat("A", 4096) + `|=]"` + "\n")},
		{"invalidutf8", withRule(string([]byte{0xff, 0xfe, 0x00, 'x', 0xc3, 0x28}))},
		{"empty", siem.Event{}},
		{"permanent", func() siem.Event {
			e := baseEvent()
			e.Strike = 5
			e.TTL = 0
			e.Rule = "5th strike: permanent ban"
			return e
		}()},
		{"system", siem.Event{
			Time:    fixedTime,
			Action:  "arm",
			Rule:    "operator armed enforcement",
			Actor:   "manual",
			Node:    "edge-01",
			Vendor:  "ezy",
			Product: "EzyShield",
			Version: "1.4.2",
		}},
		{"multi", func() siem.Event {
			e := baseEvent()
			e.Rule = poison
			e.Actor = poison
			e.Node = poison
			return e
		}()},
	}
}

// renderBundle renders all three formats into one deterministic, single-line-per
// -format blob. Because every formatter is guaranteed to emit exactly one line,
// the "\n" section separators are unambiguous — a stray newline in any field
// would corrupt the bundle, which the invariant checks catch independently.
func renderBundle(t *testing.T, e siem.Event) string {
	t.Helper()
	jb, err := siem.FormatJSON(e)
	if err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	var b strings.Builder
	b.WriteString("--- json ---\n")
	b.Write(jb)
	b.WriteString("\n--- cef ---\n")
	b.WriteString(siem.FormatCEF(e))
	b.WriteString("\n--- rfc5424 ---\n")
	b.WriteString(siem.FormatRFC5424(e))
	b.WriteString("\n")
	return b.String()
}

// TestFormatters_Golden renders every case and compares against its golden
// bundle, then asserts the format invariants hold for that case.
func TestFormatters_Golden(t *testing.T) {
	for _, c := range formatterCases() {
		t.Run(c.name, func(t *testing.T) {
			bundle := renderBundle(t, c.event)
			path := filepath.Join("..", "..", "fixtures", "siem", c.name+".golden")

			if *update {
				if err := os.WriteFile(path, []byte(bundle), 0o600); err != nil { //nolint:gosec // G304: test-controlled fixture path
					t.Fatalf("update golden: %v", err)
				}
			}

			want, err := os.ReadFile(path) //nolint:gosec // G304: test-controlled fixture path
			if err != nil {
				t.Fatalf("read golden (run with -update to create): %v", err)
			}
			if bundle != string(want) {
				t.Errorf("golden mismatch for %s\n--- got ---\n%s\n--- want ---\n%s",
					c.name, bundle, want)
			}

			assertInvariants(t, c.event)
		})
	}
}

// TestCapBoundsRenderedFields confirms the length cap actually bounds the
// rendered JSON field, not just the internal helper: a 4 KB rule must not
// produce a 4 KB "rule" value.
func TestCapBoundsRenderedFields(t *testing.T) {
	e := withRule(strings.Repeat("A", 4096))
	jb, err := siem.FormatJSON(e)
	if err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	var decoded struct {
		Rule string `json:"rule"`
	}
	if err := json.Unmarshal(jb, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// 512 is the documented cap (siem.maxFieldLen); see docs/schemas/siem.
	if len(decoded.Rule) > 512 {
		t.Fatalf("rule length = %d, want <= 512", len(decoded.Rule))
	}
}

// --- invariant validators (shared with the fuzz test) ---

// assertInvariants checks the security-critical output properties for all three
// formats: valid JSON, no raw newline, no leftover ANSI ESC, and a well-formed,
// non-injectable structure for CEF and RFC 5424.
func assertInvariants(t *testing.T, e siem.Event) {
	t.Helper()

	jb, err := siem.FormatJSON(e)
	if err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	if !json.Valid(jb) {
		t.Errorf("JSON output is not valid JSON: %q", jb)
	}
	if hasRawNewline(string(jb)) {
		t.Errorf("JSON output contains a raw newline: %q", jb)
	}

	cef := siem.FormatCEF(e)
	checkNoRawControl(t, "CEF", cef)
	checkCEFStructure(t, cef)

	sl := siem.FormatRFC5424(e)
	checkNoRawControl(t, "RFC5424", sl)
	if !strings.HasPrefix(sl, "<") {
		t.Errorf("RFC5424 output missing PRI prefix: %q", sl)
	}
	if !rfc5424SDWellFormed(sl) {
		t.Errorf("RFC5424 structured-data is not well-formed / has an unescaped delimiter: %q", sl)
	}
}

func hasRawNewline(s string) bool {
	return strings.ContainsAny(s, "\n\r")
}

// checkNoRawControl asserts the output has no raw newline and no ANSI ESC byte
// — both are log-forging vectors that the escapers must neutralise.
func checkNoRawControl(t *testing.T, format, out string) {
	t.Helper()
	if hasRawNewline(out) {
		t.Errorf("%s output contains a raw newline: %q", format, out)
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("%s output contains a raw ANSI ESC: %q", format, out)
	}
}

// checkCEFStructure asserts the seven pipe-delimited header fields are intact
// (an attacker-controlled field cannot introduce or collapse a header column)
// and that the severity field is a valid 0..10 integer.
func checkCEFStructure(t *testing.T, cef string) {
	t.Helper()
	fields := splitUnescapedPipe(cef)
	if len(fields) < 8 {
		t.Fatalf("CEF has %d fields, want >= 8: %q", len(fields), cef)
	}
	if fields[0] != "CEF:0" {
		t.Errorf("CEF prefix = %q, want CEF:0", fields[0])
	}
	sev, err := strconv.Atoi(fields[6])
	if err != nil || sev < 0 || sev > 10 {
		t.Errorf("CEF severity field = %q, want integer 0..10", fields[6])
	}
}

// splitUnescapedPipe splits a CEF line on '|' characters that are not
// backslash-escaped. The first seven splits are the header separators; header
// fields escape '|', so extra fields can only come from the (harmless)
// extension, never from a header value.
func splitUnescapedPipe(s string) []string {
	var fields []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if c == '|' {
			fields = append(fields, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	fields = append(fields, cur.String())
	return fields
}

// rfc5424SDWellFormed parses the STRUCTURED-DATA element with escape awareness
// and reports whether it is well-formed: every SD-PARAM value is a quoted
// string in which '"', ']' and control characters appear only escaped. A bare
// '"' or ']' inside a value — i.e. a failed escape — makes this return false,
// which is exactly the injection the escaper must prevent.
func rfc5424SDWellFormed(line string) bool {
	// The SD-ID is a stable contract (see siem.sdID); hard-code it here so the
	// external test verifies the wire format rather than an internal constant.
	start := strings.Index(line, "[ezyShield@32473")
	if start < 0 {
		return false
	}
	s := line[start:]
	i := 1 // past '['
	for i < len(s) && s[i] != ' ' && s[i] != ']' {
		i++ // skip SD-ID
	}
	for i < len(s) {
		if s[i] == ']' {
			return true // SD element closed cleanly
		}
		if s[i] != ' ' {
			return false
		}
		i++ // SP before PARAM
		for i < len(s) && s[i] != '=' && s[i] != ' ' && s[i] != ']' {
			i++ // PARAM-NAME
		}
		if i >= len(s) || s[i] != '=' {
			return false
		}
		i++
		if i >= len(s) || s[i] != '"' {
			return false
		}
		i++ // opening quote
		for i < len(s) {
			switch s[i] {
			case '\\':
				i += 2 // escaped char: \\ \" \]
				continue
			case '"':
				// closing quote
			case ']', '\n', '\r':
				return false // bare delimiter inside value → injection
			default:
				i++
				continue
			}
			break
		}
		if i >= len(s) || s[i] != '"' {
			return false
		}
		i++ // closing quote
	}
	return false // SD element never closed
}
