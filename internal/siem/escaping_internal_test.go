package siem

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// TestCapField verifies the length cap is enforced in bytes and never splits a
// multi-byte rune at the boundary.
func TestCapField(t *testing.T) {
	t.Run("short string is unchanged", func(t *testing.T) {
		s := "hello"
		if got := capField(s); got != s {
			t.Fatalf("capField(%q) = %q, want unchanged", s, got)
		}
	})

	t.Run("ascii is capped to maxFieldLen bytes", func(t *testing.T) {
		s := strings.Repeat("A", maxFieldLen+100)
		got := capField(s)
		if len(got) != maxFieldLen {
			t.Fatalf("len = %d, want %d", len(got), maxFieldLen)
		}
	})

	t.Run("does not split a multi-byte rune", func(t *testing.T) {
		// "€" is 3 bytes. Fill just past the cap with them so the cut lands
		// mid-rune; the result must remain valid UTF-8 and be <= maxFieldLen.
		s := strings.Repeat("€", maxFieldLen) // 3*maxFieldLen bytes
		got := capField(s)
		if len(got) > maxFieldLen {
			t.Fatalf("len = %d, want <= %d", len(got), maxFieldLen)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("capField split a rune: result is not valid UTF-8")
		}
		// At most 2 bytes are dropped below the cap to reach a rune boundary.
		if len(got) < maxFieldLen-2 {
			t.Fatalf("len = %d, dropped more than one rune's worth", len(got))
		}
	})
}

// TestCEFEscapeHeader checks that the two header metacharacters are escaped and
// control characters are neutralised.
func TestCEFEscapeHeader(t *testing.T) {
	cases := []struct{ in, want string }{
		{`plain`, `plain`},
		{`a|b`, `a\|b`},
		{`a\b`, `a\\b`},
		{`a\|b`, `a\\\|b`},
		{"a\nb", `a\nb`},
		{"a\rb", `a\rb`},
		{"a\x1bb", `a b`}, // ANSI ESC neutralised to space
		{"a\x00b", `a b`}, // NUL neutralised
		{"a\x7fb", `a b`}, // DEL neutralised
	}
	for _, c := range cases {
		if got := cefEscapeHeader(c.in); got != c.want {
			t.Errorf("cefEscapeHeader(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCEFEscapeExtension checks '\' and '=' escaping plus control neutralisation.
func TestCEFEscapeExtension(t *testing.T) {
	cases := []struct{ in, want string }{
		{`plain`, `plain`},
		{`k=v`, `k\=v`},
		{`a\b`, `a\\b`},
		{`a|b`, `a|b`}, // pipe is not a metacharacter in the extension
		{"a\nb", `a\nb`},
		{"a\x1bb", `a b`},
	}
	for _, c := range cases {
		if got := cefEscapeExtension(c.in); got != c.want {
			t.Errorf("cefEscapeExtension(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSDEscape checks RFC 5424 §6.3.3 escaping of '"', '\' and ']'.
func TestSDEscape(t *testing.T) {
	cases := []struct{ in, want string }{
		{`plain`, `plain`},
		{`a"b`, `a\"b`},
		{`a\b`, `a\\b`},
		{`a]b`, `a\]b`},
		{`]"\`, `\]\"\\`},
		{"a\nb", `a b`},   // newline neutralised (no raw newline in SD)
		{"a\x1bb", `a b`}, // ANSI ESC neutralised
	}
	for _, c := range cases {
		if got := sdEscape(c.in); got != c.want {
			t.Errorf("sdEscape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSyslogToken checks header-token reduction and NILVALUE fallback.
func TestSyslogToken(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"host-01", 255, "host-01"},
		{"has space", 255, "hasspace"}, // spaces dropped (token, not free text)
		{"a\nb", 255, "ab"},            // control dropped
		{"", 255, "-"},                 // NILVALUE
		{"   ", 255, "-"},              // only spaces → NILVALUE
		{"abcdef", 3, "abc"},           // capped
	}
	for _, c := range cases {
		if got := syslogToken(c.in, c.max); got != c.want {
			t.Errorf("syslogToken(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}

// TestSeverityMapping documents and locks the action/strike → severity mapping
// on both scales (CEF 0..10, syslog 0..7 with lower = more severe).
func TestSeverityMapping(t *testing.T) {
	cases := []struct {
		name       string
		e          Event
		wantCEF    int
		wantSyslog int
	}{
		{"permanent ban", Event{Action: "ban", Strike: 5}, 10, 2},
		{"late-strike ban", Event{Action: "ban", Strike: 3}, 8, 3},
		{"early-strike ban", Event{Action: "ban", Strike: 1}, 6, 4},
		{"simulated ban", Event{Action: "dry_ban"}, 4, 5},
		{"notify only", Event{Action: "notify_only"}, 4, 5},
		{"unban", Event{Action: "unban"}, 2, 6},
		{"expire", Event{Action: "expire"}, 2, 6},
		{"unknown op", Event{Action: "weird"}, 4, 5}, // falls back to Low, never Info
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cefSeverity(c.e); got != c.wantCEF {
				t.Errorf("cefSeverity = %d, want %d", got, c.wantCEF)
			}
			if got := syslogSeverity(c.e); got != c.wantSyslog {
				t.Errorf("syslogSeverity = %d, want %d", got, c.wantSyslog)
			}
		})
	}
}

// TestRFC3339UTC checks zero-time handling and UTC normalisation.
func TestRFC3339UTC(t *testing.T) {
	if got := rfc3339UTC(time.Time{}); got != "" {
		t.Errorf("zero time = %q, want empty", got)
	}
	// A non-UTC input is normalised to UTC (Z suffix).
	loc := time.FixedZone("x", 2*60*60)
	in := time.Date(2025, 1, 15, 12, 0, 0, 0, loc)
	if got := rfc3339UTC(in); got != "2025-01-15T10:00:00Z" {
		t.Errorf("got %q, want 2025-01-15T10:00:00Z", got)
	}
}

// TestIPStringOmitsZero verifies the zero IP renders as empty (not "invalid IP").
func TestIPStringOmitsZero(t *testing.T) {
	if got := (Event{}).ipString(); got != "" {
		t.Errorf("zero IP ipString() = %q, want empty", got)
	}
}
