package ai

import (
	"encoding/json"
	"fmt"
	"strings"
)

// parseVerdictJSON unmarshals an AI provider's raw text response into dst.
//
// It transparently strips a leading Markdown code fence — Claude Haiku 4.5 (and
// several other modern chat models) frequently wrap JSON responses in
// ```json … ``` even when the prompt explicitly asks for raw JSON. Without
// this preprocessing json.Unmarshal fails with "invalid character '`' looking
// for beginning of value" and burns tokens for zero verdicts (see issue #21).
//
// Accepted shapes (case-insensitive on the language hint):
//
//	{"results": ...}
//	```json\n{"results": ...}\n```
//	```JSON\r\n{"results": ...}\r\n```
//	   ```   \n{"results": ...}\n```   (whitespace-tolerant on both ends)
//
// A malformed JSON body after strip still returns an error — the strip is
// intentionally forgiving of the wrapper, strict about the payload.
func parseVerdictJSON(text string, dst any) error {
	trimmed := strings.TrimSpace(text)
	body := stripCodeFence(trimmed)
	if err := json.Unmarshal([]byte(body), dst); err != nil {
		return fmt.Errorf("parse verdict JSON: %w", err)
	}
	return nil
}

// stripCodeFence removes a leading ```<lang>?\n and a trailing \n``` from s
// when both are present. If either fence is missing, s is returned as-is so
// callers that pass raw JSON keep working. The check is line-oriented so an
// unrelated backtick appearing inside the JSON body (e.g. inside a "reason"
// string) does not confuse the strip.
func stripCodeFence(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	// Drop everything up to and including the first newline of the opening
	// fence — that captures "```", "```json", "```JSON", "```  json  ", etc.
	openNL := strings.IndexByte(s, '\n')
	if openNL < 0 {
		// Single-line "```json{...}```" isn't a shape we've seen in practice
		// and would be ambiguous to parse safely, so leave it to Unmarshal to
		// reject with a normal JSON error.
		return s
	}
	body := s[openNL+1:]

	// Trim a trailing ``` (with optional whitespace / newlines around it).
	// Strip whitespace first so ``` at the very end matches regardless of a
	// stray trailing newline the model might emit.
	body = strings.TrimRight(body, " \t\r\n")
	if strings.HasSuffix(body, "```") {
		body = strings.TrimSuffix(body, "```")
		body = strings.TrimRight(body, " \t\r\n")
	}
	return body
}
