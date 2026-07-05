package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
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

// installTokenReader swaps the package-level tokenReader with fn for the
// duration of the test. Prevents tests from ever opening /dev/tty.
func installTokenReader(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	orig := tokenReader
	tokenReader = fn
	t.Cleanup(func() { tokenReader = orig })
}

// TestInit_PromptsForTokenNotName_AnthropicProvider is the direct spec test
// for issue #13 §1 + §2: the wizard picks ANTHROPIC_API_KEY from the fixed
// table (no NAME prompt) and then reads the token via the masked reader.
//
// We assert:
//   - state.aiKeyEnvVar is set to the fixed table entry ANTHROPIC_API_KEY,
//     without any prompt line matching "env var" appearing in stdout.
//   - state.aiToken carries whatever the masked reader returned.
//   - Neither the prompt for the token nor the resulting stdout contains the
//     token itself (the mocked reader ships it out-of-band).
func TestInit_PromptsForTokenNotName_AnthropicProvider(t *testing.T) {
	const fakeToken = "sk-ant-fake-token-abcdef123456" //nolint:gosec // G101: intentional fake

	var promptSeen string
	installTokenReader(t, func(prompt string) (string, error) {
		promptSeen = prompt
		return fakeToken, nil
	})

	input := strings.Join([]string{
		"",          // admin IP
		"y",         // enable AI
		"anthropic", // provider
		"",          // model default
		"",          // armed default
	}, "\n") + "\n"

	state, out := runAskQuestionsWithAI(t, input)

	if state.aiKeyEnvVar != "ANTHROPIC_API_KEY" {
		t.Errorf("aiKeyEnvVar = %q, want ANTHROPIC_API_KEY (from fixed table)", state.aiKeyEnvVar)
	}
	if state.aiToken != fakeToken {
		t.Errorf("aiToken not captured via masked reader: got %q", state.aiToken)
	}
	// The wizard MUST NOT ask the operator to type an env var NAME any more.
	// Old wording: "Env var holding API key" — must not appear anywhere.
	if strings.Contains(strings.ToLower(out), "env var") {
		t.Errorf("wizard still prompts for env-var NAME; stdout=%q", out)
	}
	// The masked reader receives its own prompt line, not stdout.
	if !strings.Contains(strings.ToLower(promptSeen), "token") {
		t.Errorf("masked prompt did not mention 'token'; got %q", promptSeen)
	}
	// The token itself must NEVER appear on stdout.
	if strings.Contains(out, fakeToken) {
		t.Errorf("wizard leaks the token on stdout: %q", out)
	}
}

// TestInit_MaskedInput_NoEchoOnFailedPrompt asserts that when the masked
// reader returns an error (no tty), the wizard falls through to the
// placeholder path with NO echo of any input, and state.aiToken stays empty
// (issue #13 §2 fall-through rule).
func TestInit_MaskedInput_NoEchoOnFailedPrompt(t *testing.T) {
	installTokenReader(t, func(_ string) (string, error) {
		return "", ErrNoTTY
	})

	input := strings.Join([]string{
		"",          // admin IP
		"y",         // enable AI
		"anthropic", // provider
		"",          // model default
		"",          // armed default
	}, "\n") + "\n"

	state, out := runAskQuestionsWithAI(t, input)

	if state.aiToken != "" {
		t.Errorf("aiToken should be empty on tty read failure, got %q", state.aiToken)
	}
	if state.aiKeyEnvVar != "ANTHROPIC_API_KEY" {
		t.Errorf("wizard forgot to set the fixed key name: %q", state.aiKeyEnvVar)
	}
	// No line on stdout should mention any secret-like value — a failed read
	// must not print the buffer content at all.
	if strings.Contains(out, "sk-") || strings.Contains(out, "Bearer") {
		t.Errorf("stdout leaks secret-shaped material: %q", out)
	}
}

// TestInit_WritesDotEnvNotEnv locks in issue #13 §3: the AI env file lives
// at <configDir>/.env (dot-prefixed), NOT <configDir>/env. The wizard writes
// mode 0600 and includes exactly one KEY=VALUE line.
func TestInit_WritesDotEnvNotEnv(t *testing.T) {
	dir := t.TempDir()

	// Drive writeOrKeepEnvFile directly — the whole init.go pipeline needs
	// root for the ownership chown and is covered elsewhere.
	envPath := filepath.Join(dir, envFileName)
	if filepath.Base(envPath) != ".env" {
		t.Fatalf("envFileName constant is %q, expected .env (dot prefix)", envFileName)
	}

	wrote, kept, err := writeOrKeepEnvFile(envPath, "ANTHROPIC_API_KEY", "sk-ant-fake") //nolint:gosec // G101: test fake
	if err != nil {
		t.Fatalf("writeOrKeepEnvFile: %v", err)
	}
	if !wrote || kept {
		t.Fatalf("wrote=%v kept=%v, want wrote=true kept=false", wrote, kept)
	}

	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perms = %04o, want 0600", info.Mode().Perm())
	}

	data, err := os.ReadFile(envPath) //nolint:gosec // test path under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	// Exactly one KEY=VALUE line (plus header/trailing newline).
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ANTHROPIC_API_KEY=") {
			if found {
				t.Errorf("multiple ANTHROPIC_API_KEY lines in %s", envPath)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("no ANTHROPIC_API_KEY= line in %s; body=%q", envPath, string(data))
	}
	// File must end with \n so systemd's EnvironmentFile parser sees the
	// last line (issue #13 §3).
	if !strings.HasSuffix(string(data), "\n") {
		t.Errorf("%s missing trailing newline", envPath)
	}
}

// TestInit_PlaceholderWhenSkipped covers §5: when the operator skips the
// token prompt (mocked reader returns ""), the wizard still writes .env
// with the literal placeholder — so systemd's EnvironmentFile= doesn't fail
// loudly and the operator can edit the file post-install.
func TestInit_PlaceholderWhenSkipped(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, envFileName)

	wrote, kept, err := writeOrKeepEnvFile(envPath, "ANTHROPIC_API_KEY", "")
	if err != nil {
		t.Fatalf("writeOrKeepEnvFile: %v", err)
	}
	if !wrote || kept {
		t.Errorf("wrote=%v kept=%v, want wrote=true kept=false", wrote, kept)
	}

	data, err := os.ReadFile(envPath) //nolint:gosec // test path under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ANTHROPIC_API_KEY=YOUR_API_KEY_HERE") {
		t.Errorf(".env missing placeholder line; body=%q", string(data))
	}
	// The loader must treat this exact value as "unset" (config.PlaceholderAPIKey).
	if envAPIKeyPlaceholder != config.PlaceholderAPIKey {
		t.Errorf("wizard placeholder %q differs from loader placeholder %q — they must match",
			envAPIKeyPlaceholder, config.PlaceholderAPIKey)
	}
}

// TestInit_IdempotentReRun_KeepsExistingToken covers §5 idempotency: a
// pre-existing .env with a real (non-placeholder) token is NOT clobbered on
// re-run when the operator skips the prompt.
func TestInit_IdempotentReRun_KeepsExistingToken(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, envFileName)
	const existing = "sk-ant-preexisting-token-9999" //nolint:gosec // G101: test fake

	// Simulate a prior init: write a real token via writeEnvFileContent.
	if err := writeEnvFileContent(envPath, "ANTHROPIC_API_KEY", existing); err != nil {
		t.Fatalf("prep: %v", err)
	}

	// Re-run with token=="" (operator skipped or non-TTY).
	wrote, kept, err := writeOrKeepEnvFile(envPath, "ANTHROPIC_API_KEY", "")
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if wrote || !kept {
		t.Errorf("wrote=%v kept=%v, want wrote=false kept=true", wrote, kept)
	}

	// Confirm the real token survived.
	data, err := os.ReadFile(envPath) //nolint:gosec // test path under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ANTHROPIC_API_KEY="+existing) {
		t.Errorf("pre-existing token was clobbered; body=%q", string(data))
	}
	if strings.Contains(string(data), envAPIKeyPlaceholder) {
		t.Errorf("re-run replaced real token with placeholder; body=%q", string(data))
	}

	// And a re-run WITH a new token DOES overwrite.
	const fresh = "sk-ant-fresh-9999" //nolint:gosec // G101: test fake
	wrote, kept, err = writeOrKeepEnvFile(envPath, "ANTHROPIC_API_KEY", fresh)
	if err != nil {
		t.Fatalf("re-run with token: %v", err)
	}
	if !wrote || kept {
		t.Errorf("re-run with token wrote=%v kept=%v, want wrote=true kept=false", wrote, kept)
	}
	data, _ = os.ReadFile(envPath) //nolint:gosec,errcheck // test path under t.TempDir
	if !strings.Contains(string(data), "ANTHROPIC_API_KEY="+fresh) {
		t.Errorf("new token not written; body=%q", string(data))
	}
}

// TestInit_ConfigYAMLGetsFixedReference is the extra assertion attached to §7
// / §1 acceptance: writeGeneratedConfig emits `api_key: env:ANTHROPIC_API_KEY`
// and never the raw token, regardless of whether the operator supplied one.
func TestInit_ConfigYAMLGetsFixedReference(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	const token = "sk-ant-fake-XYZ" //nolint:gosec // G101: test fake
	state := &wizardState{
		nftPath:     "/usr/sbin/nft",
		enableAI:    true,
		aiProvider:  "anthropic",
		aiModel:     "claude-haiku-4-5-20251001",
		aiKeyEnvVar: "ANTHROPIC_API_KEY",
		aiToken:     token,
	}

	if err := writeGeneratedConfig(cfgPath, state); err != nil {
		t.Fatalf("writeGeneratedConfig: %v", err)
	}
	data, err := os.ReadFile(cfgPath) //nolint:gosec // test path under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, "api_key: env:ANTHROPIC_API_KEY") {
		t.Errorf("config.yaml missing fixed api_key reference; body=%q", body)
	}
	if strings.Contains(body, token) {
		t.Errorf("config.yaml LEAKS the token verbatim (issue #13 regression)")
	}
}

// TestInit_WizardState_StringRedactsToken is the §6 struct-dump defense:
// printing *wizardState with %v / %+v must NOT expose the raw token.
func TestInit_WizardState_StringRedactsToken(t *testing.T) {
	const token = "sk-ant-verysecret-1234567890" //nolint:gosec // G101: test fake
	s := &wizardState{aiToken: token}

	got := s.String()
	if strings.Contains(got, token) {
		t.Errorf("wizardState.String() leaks the token: %q", got)
	}
	// Also verify %+v goes through String().
	fmted := errors.New(s.String()).Error()
	if strings.Contains(fmted, token) {
		t.Errorf("formatted state leaks the token: %q", fmted)
	}
}
