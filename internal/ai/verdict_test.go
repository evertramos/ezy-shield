package ai

import (
	"strings"
	"testing"
)

// TestParseVerdictJSON covers every wrapper shape observed or plausibly emitted
// by an upstream chat model, and confirms plain JSON still round-trips.
func TestParseVerdictJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{
			name: "plain JSON — backward compat, must not regress the openai/ollama path",
			in:   `{"results":[{"ip":"1.2.3.4","score":80,"category":"scanner","confidence":0.9,"reason":"probing","suggest_ttl_seconds":300}]}`,
		},
		{
			name: "fence with json language hint — the Claude Haiku default in issue #21",
			in: "```json\n" +
				`{"results":[{"ip":"1.2.3.4","score":80,"category":"scanner","confidence":0.9,"reason":"probing","suggest_ttl_seconds":300}]}` +
				"\n```",
		},
		{
			name: "fence without language hint",
			in: "```\n" +
				`{"results":[{"ip":"1.2.3.4","score":80,"category":"scanner","confidence":0.9,"reason":"probing","suggest_ttl_seconds":300}]}` +
				"\n```",
		},
		{
			name: "uppercase language hint — some models normalize like this",
			in: "```JSON\n" +
				`{"results":[{"ip":"1.2.3.4","score":80,"category":"scanner","confidence":0.9,"reason":"probing","suggest_ttl_seconds":300}]}` +
				"\n```",
		},
		{
			name: "leading + trailing whitespace around the whole thing",
			in: "   \n\n```json\n" +
				`{"results":[{"ip":"1.2.3.4","score":80,"category":"scanner","confidence":0.9,"reason":"probing","suggest_ttl_seconds":300}]}` +
				"\n```\n\n   ",
		},
		{
			name: "CRLF line endings — Windows-flavoured models",
			in: "```json\r\n" +
				`{"results":[{"ip":"1.2.3.4","score":80,"category":"scanner","confidence":0.9,"reason":"probing","suggest_ttl_seconds":300}]}` +
				"\r\n```",
		},
		{
			name: "backtick inside a reason string — must NOT get eaten by the strip",
			in: "```json\n" +
				`{"results":[{"ip":"1.2.3.4","score":80,"category":"scanner","confidence":0.9,"reason":"hit ` + "`admin.php`" + ` probe","suggest_ttl_seconds":300}]}` +
				"\n```",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got verdictSchema
			if err := parseVerdictJSON(tc.in, &got); err != nil {
				t.Fatalf("parseVerdictJSON: %v", err)
			}
			if len(got.Results) != 1 {
				t.Fatalf("want 1 result, got %d", len(got.Results))
			}
			if got.Results[0].IP != "1.2.3.4" || got.Results[0].Score != 80 {
				t.Errorf("payload not parsed correctly: %+v", got.Results[0])
			}
		})
	}
}

// TestParseVerdictJSON_MalformedBody: a malformed payload after strip must
// still surface an error — the strip is forgiving of the wrapper, not of the
// body.
func TestParseVerdictJSON_MalformedBody(t *testing.T) {
	in := "```json\n{not: valid}\n```"
	var got verdictSchema
	err := parseVerdictJSON(in, &got)
	if err == nil {
		t.Fatal("expected an error for malformed JSON body, got nil")
	}
	if !strings.HasPrefix(err.Error(), "parse verdict JSON:") {
		t.Errorf("expected wrapped error, got: %v", err)
	}
}

// TestParseVerdictJSON_Regression_Issue21 reproduces the exact input shape
// that broke the Anthropic provider on kylian-s (2026-07-03 06:28 UTC) and
// asserts the fix handles it. If this ever fails, the strip has regressed.
func TestParseVerdictJSON_Regression_Issue21(t *testing.T) {
	// Actual body Haiku returns — a code-fenced JSON object with the
	// backtick as the very first character. Before the fix, json.Unmarshal
	// errored with: `invalid character '`' looking for beginning of value`.
	in := "```json\n" +
		`{"results":[{"ip":"20.104.50.116","score":72,"category":"scanner","confidence":0.85,"reason":"webshell probing","suggest_ttl_seconds":600}]}` +
		"\n```"
	var got verdictSchema
	if err := parseVerdictJSON(in, &got); err != nil {
		t.Fatalf("regression: %v", err)
	}
	if len(got.Results) != 1 || got.Results[0].IP != "20.104.50.116" {
		t.Fatalf("regression: unexpected payload: %+v", got)
	}
}

// TestStripCodeFence: unit-test the strip helper directly for edge cases the
// higher-level test doesn't cover.
func TestStripCodeFence(t *testing.T) {
	cases := []struct {
		name string
		in   string
		out  string
	}{
		{"no fence", `{"x":1}`, `{"x":1}`},
		{"fence with json", "```json\n{\"x\":1}\n```", `{"x":1}`},
		{"fence uppercase", "```JSON\n{\"x\":1}\n```", `{"x":1}`},
		{"single-line — left to json.Unmarshal to reject", "```json{\"x\":1}```", "```json{\"x\":1}```"},
		{"only opening fence, no close — still strips the opener", "```json\n{\"x\":1}", `{"x":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripCodeFence(tc.in); got != tc.out {
				t.Errorf("stripCodeFence(%q) = %q, want %q", tc.in, got, tc.out)
			}
		})
	}
}
