package main

import (
	"bufio"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// whatever fn wrote. Prompts in askQuestions go through fmt.Printf → stdout,
// so we must capture the real fd, not a bytes.Buffer.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() {
		_ = w.Close()
		os.Stdout = orig
	}()
	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

// runAskQuestionsWithAI is a minimal driver: feeds `input` on stdin,
// disables everything except the AI branch, and returns the final state
// plus whatever the wizard printed to stdout. It matches the exact prompt
// order in askQuestions so tests only have to line up the AI answers.
func runAskQuestionsWithAI(t *testing.T, input string) (*wizardState, string) {
	t.Helper()
	state := &wizardState{
		// No web servers, no SSH unit, no admin IP → prompts collapse to nothing
		// before we reach the AI section.
		webServers:  nil,
		sshUnit:     "",
		publicIP:    "",
		sshSourceIP: "",
	}
	sc := bufio.NewScanner(strings.NewReader(input))
	out := captureStdout(t, func() {
		askQuestions(sc, state, false)
	})
	return state, out
}

// TestAskEnvVar_AcceptsPlainName confirms the happy path: typing
// ANTHROPIC_API_KEY at the prompt yields state.aiKeyEnvVar == that name.
// Input sequence (matches prompt order in askQuestions):
//
//	""                     — no admin IP
//	"y"                    — Enable AI analysis
//	"anthropic"            — provider
//	"claude-haiku-4-5-..." — model default
//	"ANTHROPIC_API_KEY"    — env var name (valid)
//	""                     — armed default
func TestAskEnvVar_AcceptsPlainName(t *testing.T) {
	input := strings.Join([]string{
		"",                  // admin IP (empty → default empty)
		"y",                 // enable AI
		"anthropic",         // provider
		"",                  // model (accept default)
		"ANTHROPIC_API_KEY", // env var name (valid identifier)
		"",                  // armed (accept default)
	}, "\n") + "\n"

	state, out := runAskQuestionsWithAI(t, input)

	if state.aiKeyEnvVar != "ANTHROPIC_API_KEY" {
		t.Errorf("aiKeyEnvVar = %q, want ANTHROPIC_API_KEY", state.aiKeyEnvVar)
	}
	if strings.Contains(out, "rejected:") {
		t.Errorf("wizard rejected a valid identifier; stdout=%q", out)
	}
}

// TestAskEnvVar_RejectsPastedKey is the direct regression for issue #13.
// The operator pastes their real API key at the env-var-name prompt; the
// wizard must (a) reject it, (b) not echo the raw value in the rejection
// message, and (c) re-prompt so a valid identifier can be supplied.
func TestAskEnvVar_RejectsPastedKey(t *testing.T) {
	// Obviously-fake, never a real credential.
	const pastedKey = "sk-ant-fake-1234567890123456789012345"

	input := strings.Join([]string{
		"",                  // admin IP
		"y",                 // enable AI
		"anthropic",         // provider
		"",                  // model default
		pastedKey,           // 1st attempt: pasted key — must be rejected
		"ANTHROPIC_API_KEY", // 2nd attempt: valid name
		"",                  // armed default
	}, "\n") + "\n"

	state, out := runAskQuestionsWithAI(t, input)

	if state.aiKeyEnvVar != "ANTHROPIC_API_KEY" {
		t.Errorf("wizard did not recover to valid identifier: aiKeyEnvVar=%q", state.aiKeyEnvVar)
	}
	if !strings.Contains(out, "rejected:") {
		t.Errorf("wizard did not print a rejection message; stdout=%q", out)
	}
	if strings.Contains(out, pastedKey) {
		t.Errorf("rejection message leaks the pasted secret verbatim (issue #13 regression)\nstdout=%q", out)
	}
	// Fingerprint of the pasted key ("sk-a") is fine — it's the first 4 chars
	// only. Make sure the tail (the actually-secret bit) is not present.
	tail := pastedKey[8:]
	if strings.Contains(out, tail) {
		t.Errorf("stdout contains tail of pasted key (%q); redaction insufficient", tail)
	}
}

// TestAskEnvVar_RejectsShellUnsafeName covers non-secret-shaped invalid input:
// a name with a dash is not a POSIX identifier. It must be rejected the same way,
// so operators can't accidentally invent names that break shell env passing.
func TestAskEnvVar_RejectsShellUnsafeName(t *testing.T) {
	input := strings.Join([]string{
		"",                  // admin IP
		"y",                 // enable AI
		"anthropic",         // provider
		"",                  // model default
		"MY-API-KEY",        // invalid: dashes forbidden
		"ANTHROPIC_API_KEY", // recovery
		"",                  // armed default
	}, "\n") + "\n"

	state, out := runAskQuestionsWithAI(t, input)

	if state.aiKeyEnvVar != "ANTHROPIC_API_KEY" {
		t.Errorf("aiKeyEnvVar = %q, want ANTHROPIC_API_KEY", state.aiKeyEnvVar)
	}
	if !strings.Contains(out, "rejected:") {
		t.Errorf("wizard did not reject shell-unsafe name; stdout=%q", out)
	}
}
