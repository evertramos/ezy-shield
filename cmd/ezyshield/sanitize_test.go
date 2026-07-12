package main

import (
	"strings"
	"testing"
)

// TestSanitizeField_HostileBytes is the terminal-injection gate required by
// issue #105 (§1 SECURITY-REVIEW): event fields carrying bytes copied from
// hostile log lines must come out inert — no escape sequences, no control
// characters, no invalid UTF-8.
func TestSanitizeField_HostileBytes(t *testing.T) {
	const max = 200
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain ascii", "sshd brute force", "sshd brute force"},
		{"unicode preserved", "café ☂ 東京", "café ☂ 東京"},
		{"csi color", "\x1b[31mFAKE BAN\x1b[0m", "FAKE BAN"},
		{"csi cursor and clear", "\x1b[2J\x1b[1;1Hspoofed", "spoofed"},
		{"csi with params", "user \x1b[38;5;196madmin\x1b[0m", "user admin"},
		{"osc title bel", "\x1b]0;owned\x07rest", "rest"},
		{"osc title st", "\x1b]2;owned\x1b\\rest", "rest"},
		{"single char escape", "a\x1bcb", "ab"},
		{"bare esc at end", "trailing\x1b", "trailing"},
		{"unterminated csi", "x\x1b[31", "x"},
		{"malformed csi stops", "\x1b[12\x80x", "x"},
		{"c0 controls", "a\x00b\x01c\x08d", "abcd"},
		{"crlf and tab", "line1\r\nline2\tend", "line1line2end"},
		{"del", "a\x7fb", "ab"},
		{"c1 rune", "a\u009bb", "ab"},
		{"raw c1 byte 0x9b", "a\x9b31mb", "a31mb"},
		{"raw c1 byte 0x90", "a\x90b", "ab"},
		{"invalid utf8", "a\xff\xfeb", "ab"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeField(tc.in, max)
			if got != tc.want {
				t.Errorf("sanitizeField(%q) = %q, want %q", tc.in, got, tc.want)
			}
			assertInert(t, got)
		})
	}
}

func TestSanitizeField_Truncation(t *testing.T) {
	got := sanitizeField(strings.Repeat("x", 50), 10)
	if got != strings.Repeat("x", 10)+"…" {
		t.Errorf("truncation = %q, want 10 x's + ellipsis", got)
	}
	// Truncation counts runes, not bytes (multi-byte runes must not be split).
	got = sanitizeField(strings.Repeat("é", 50), 10)
	if got != strings.Repeat("é", 10)+"…" {
		t.Errorf("rune truncation = %q, want 10 é's + ellipsis", got)
	}
	// Exactly max runes: no ellipsis.
	if got := sanitizeField("abc", 3); got != "abc" {
		t.Errorf("exact-length input = %q, want abc", got)
	}
}

// assertInert fails if s contains anything a terminal could interpret:
// ESC, C0 controls, DEL, or C1 controls.
func assertInert(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Errorf("output %q contains control rune %U", s, r)
		}
	}
	if strings.ContainsRune(s, '\x1b') {
		t.Errorf("output %q contains ESC", s)
	}
}
