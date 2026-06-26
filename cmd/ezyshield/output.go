package main

import (
	"encoding/json"
	"fmt"
	"io"
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
