package main

import (
	"strings"
	"unicode/utf8"
)

// sanitizeField makes an untrusted string safe to print on a terminal.
// Event fields (reasons, rule names, categories) can embed content copied
// from hostile log lines — usernames, request paths — which may carry ANSI
// escape sequences or control characters designed to corrupt or spoof
// terminal output (§1 SECURITY-REVIEW: log lines are untrusted data).
//
// It strips:
//   - ESC-introduced escape sequences (CSI, OSC, and single-char escapes)
//   - all C0 control characters (including CR/LF/TAB — output is one line)
//   - DEL and the C1 control range (U+0080–U+009F, both as runes and as the
//     raw single bytes some terminals interpret, e.g. 0x9B = CSI)
//   - invalid UTF-8 bytes
//
// and caps the result at max runes, appending "…" when truncated.
func sanitizeField(s string, max int) string {
	var b strings.Builder
	b.Grow(len(s))
	kept := 0
	truncated := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == 0x1b { // ESC: swallow the whole escape sequence
			i += size
			i += escapeSeqLen(s[i:])
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			(r == utf8.RuneError && size == 1) {
			i += size
			continue
		}
		if kept >= max {
			truncated = true
			break
		}
		b.WriteRune(r)
		kept++
		i += size
	}
	if truncated {
		return b.String() + "…"
	}
	return b.String()
}

// escapeSeqLen returns how many bytes at the start of s (the bytes following
// an ESC) belong to the escape sequence, so the caller can skip them.
//
//   - CSI  (ESC '['):  parameter/intermediate bytes 0x20–0x3F, terminated by a
//     final byte 0x40–0x7E. A malformed byte ends the sequence without being
//     consumed (the main loop then strips it if it is a control char).
//   - OSC  (ESC ']'):  consumed until BEL (0x07) or ST (ESC '\').
//   - Anything else:   a single-character escape; consume one byte.
func escapeSeqLen(s string) int {
	if len(s) == 0 {
		return 0
	}
	switch s[0] {
	case '[':
		for j := 1; j < len(s); j++ {
			c := s[j]
			if c >= 0x40 && c <= 0x7e {
				return j + 1
			}
			if c < 0x20 || c > 0x3f {
				return j // malformed CSI: stop before the odd byte
			}
		}
		return len(s)
	case ']':
		for j := 1; j < len(s); j++ {
			if s[j] == 0x07 {
				return j + 1
			}
			if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' {
				return j + 2
			}
		}
		return len(s)
	default:
		return 1
	}
}
