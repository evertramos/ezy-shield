package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// writeJSON encodes v as indented JSON to w, adding a trailing newline.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

// colorEnabled reports whether ANSI-styled output should be written to w.
// This is the single color gate for the CLI (documented in the CLI reference
// as a global convention): styling is used only when the --no-color flag is
// unset, the NO_COLOR environment variable is unset (https://no-color.org),
// and w is an interactive terminal. Piped or redirected output is always
// plain.
func colorEnabled(w io.Writer) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// ── Shared terminal styling (issue #102) ─────────────────────────────────────

// ANSI SGR fragments used by styler. Exposed as constants so tests can
// assert exact bytes.
const (
	sgrReset  = "\x1b[0m"
	sgrBold   = "\x1b[1m"
	sgrDim    = "\x1b[2m"
	sgrRed    = "\x1b[31m"
	sgrGreen  = "\x1b[32m"
	sgrYellow = "\x1b[33m"
)

// headerRuleWidth is the length of the underline printed by styler.header.
const headerRuleWidth = 43

// styler renders section headers and ✓/✗/! status lines for the wizards and
// read commands, so all of them share one visual language. Whether escape
// codes are emitted is decided once, at construction, through colorEnabled
// (TTY + NO_COLOR + --no-color — the single color gate of the CLI). With
// color off the output keeps the same text and symbols, byte-stable, so
// piped output and golden tests never see escape codes.
//
// styler formats — it never sources data. Callers that print strings derived
// from untrusted input (log fields, API error bodies) must sanitize them
// first (see sanitizeField / sanitizeErrorMessage, §1 SECURITY-REVIEW.md).
type styler struct {
	color bool
}

// newStyler builds a styler whose color decision matches writes to w.
func newStyler(w io.Writer) styler { return styler{color: colorEnabled(w)} }

// paint wraps text in the given SGR code when color is on.
func (s styler) paint(code, text string) string {
	if !s.color {
		return text
	}
	return code + text + sgrReset
}

// bold and dim return emphasis variants of text.
func (s styler) bold(text string) string { return s.paint(sgrBold, text) }
func (s styler) dim(text string) string  { return s.paint(sgrDim, text) }

// header renders a section title over a dim underline rule:
//
//	Environment
//	───────────────────────────────────────────
func (s styler) header(title string) string {
	return s.bold(title) + "\n" + s.dim(strings.Repeat("─", headerRuleWidth))
}

// ok, fail, and warn render one two-space-indented status line with a
// colored ✓ / ✗ / ! mark. The message itself stays unstyled so long lines
// remain readable on any background.
func (s styler) ok(text string) string   { return "  " + s.paint(sgrGreen, "✓") + " " + text }
func (s styler) fail(text string) string { return "  " + s.paint(sgrRed, "✗") + " " + text }
func (s styler) warn(text string) string { return "  " + s.paint(sgrYellow, "!") + " " + text }
