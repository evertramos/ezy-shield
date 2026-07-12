package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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
