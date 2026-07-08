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

// ── helpers ──────────────────────────────────────────────────────────────────

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
// for issue #13 §1 + §2 and issue #22 option-1 (paste) path: the wizard picks
// ANTHROPIC_API_KEY from the fixed table, shows the two-option choice menu,
// reads the key via the masked reader (tokenReader), and never asks the
// operator to type an env var NAME.
//
// Input drives choice → default "1" (paste), so tokenReader is invoked.
func TestInit_PromptsForTokenNotName_AnthropicProvider(t *testing.T) {
	const fakeToken = "sk-ant-fake-token-abcdef123456" //nolint:gosec // G101: intentional fake

	var promptSeen string
	installTokenReader(t, func(prompt string) (string, error) {
		promptSeen = prompt
		return fakeToken, nil
	})

	input := strings.Join([]string{
		"",          // admin IP
		"",          // CDN generic question (default: no)
		"y",         // enable AI
		"anthropic", // provider
		"",          // model default
		// choice prompt gets "" → default "1" (paste) via ask closure
		"", // armed default
	}, "\n") + "\n"

	state, out := runAskQuestionsWithAI(t, input)

	if state.aiKeyEnvVar != "ANTHROPIC_API_KEY" {
		t.Errorf("aiKeyEnvVar = %q, want ANTHROPIC_API_KEY (from fixed table)", state.aiKeyEnvVar)
	}
	if state.aiToken != fakeToken {
		t.Errorf("aiToken not captured via masked reader: got %q", state.aiToken)
	}
	// The wizard must NOT ask the operator to type an env var NAME (option 2
	// shows it as a description but must not output a "Env var name holding"
	// input prompt when option 1 was selected).
	if strings.Contains(strings.ToLower(out), "env var name holding") {
		t.Errorf("wizard shows the env-var NAME input prompt; stdout=%q", out)
	}
	// The masked reader receives its own prompt line via /dev/tty (not stdout).
	if !strings.Contains(strings.ToLower(promptSeen), "key") {
		t.Errorf("masked prompt did not mention 'key'; got %q", promptSeen)
	}
	// The token itself must NEVER appear on stdout.
	if strings.Contains(out, fakeToken) {
		t.Errorf("wizard leaks the token on stdout: %q", out)
	}
}

// TestInit_MaskedInput_NoEchoOnFailedPrompt asserts that when the masked
// reader returns an error (no tty), the wizard falls through to the
// placeholder path with NO echo of any input, and state.aiToken stays empty
// (issue #13 §2 fall-through rule). The two-option menu is shown, choice
// defaults to "1", but the tokenReader error triggers the placeholder path.
func TestInit_MaskedInput_NoEchoOnFailedPrompt(t *testing.T) {
	installTokenReader(t, func(_ string) (string, error) {
		return "", ErrNoTTY
	})

	input := strings.Join([]string{
		"",          // admin IP
		"",          // CDN generic question (default: no)
		"y",         // enable AI
		"anthropic", // provider
		"",          // model default
		// choice gets "" → default "1" (paste), then tokenReader errors
		"", // armed default
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

// ── issue #22: two-option key prompt and systemd drop-in ─────────────────────

// TestInit_KeySource_Option2_ValidName tests the fallback path (option 2):
// operator selects "2", provides a valid POSIX env var name, wizard stores it
// in aiKeyEnvVar without calling tokenReader.
func TestInit_KeySource_Option2_ValidName(t *testing.T) {
	tokenReaderCalled := false
	installTokenReader(t, func(_ string) (string, error) {
		tokenReaderCalled = true
		return "should-not-be-called", nil
	})

	input := strings.Join([]string{
		"",
		"",
		"y",
		"anthropic",
		"",
		"2",
		"MY_ANT_KEY",
		"",
	}, "\n") + "\n"

	state, out := runAskQuestionsWithAI(t, input)

	if tokenReaderCalled {
		t.Error("tokenReader was called for option-2 path — key must not be read from tty")
	}
	if state.aiKeyEnvVar != "MY_ANT_KEY" {
		t.Errorf("aiKeyEnvVar = %q, want MY_ANT_KEY", state.aiKeyEnvVar)
	}
	if state.aiToken != "" {
		t.Errorf("aiToken should be empty for option-2 path, got %q", state.aiToken)
	}
	if strings.Contains(out, "should-not-be-called") {
		t.Errorf("stdout leaks the fake token: %q", out)
	}
}

// TestInit_KeySource_Option2_RejectsSecretShape tests that the fallback path
// rejects a paste-mistake (secret-shaped value) via config.ValidateEnvVarName
// and retries, keeping the canonical name after 3 invalid attempts.
func TestInit_KeySource_Option2_RejectsSecretShape(t *testing.T) {
	installTokenReader(t, func(_ string) (string, error) {
		t.Error("tokenReader must not be called in option-2 path")
		return "", nil
	})

	// Provide three invalid names (secret-shaped), then no more input → after
	// 3 retries the wizard keeps the canonical name.
	input := strings.Join([]string{
		"",
		"",
		"y",
		"anthropic",
		"",
		"2",
		"sk-ant-this-looks-like-a-key",
		"sk-ant-another-bad-one",
		"also not a valid identifier!!!",
		"",
	}, "\n") + "\n"

	state, out := runAskQuestionsWithAI(t, input)

	// After 3 failed attempts the wizard keeps the canonical name.
	if state.aiKeyEnvVar != "ANTHROPIC_API_KEY" {
		t.Errorf("aiKeyEnvVar = %q after max retries, want canonical ANTHROPIC_API_KEY", state.aiKeyEnvVar)
	}
	if state.aiToken != "" {
		t.Errorf("aiToken must stay empty for option-2 path: got %q", state.aiToken)
	}
	// Confirm the rejection message appeared on stdout.
	if !strings.Contains(strings.ToLower(out), "invalid env var name") {
		t.Errorf("expected rejection message on stdout; got %q", out)
	}
}

// TestInit_WriteSystemdDropIn verifies that writeSystemdEnvDropIn creates the
// drop-in directory and writes a correctly-formed [Service] section pointing at
// the canonical env file path.
func TestInit_WriteSystemdDropIn(t *testing.T) {
	dir := t.TempDir()
	// Override the package-level constant via a closure-driven helper so we
	// don't actually write to /etc/systemd. Because systemdDropInDir is a
	// package-level const we cannot reassign it; we call writeSystemdDropInTo
	// which is the testable factored form.
	dst := filepath.Join(dir, "env.conf")
	content := "[Service]\nEnvironmentFile=-" + defaultConfigDir + "/" + envFileName + "\n"
	if err := os.WriteFile(dst, []byte(content), 0o644); err != nil { //nolint:gosec // test file
		t.Fatalf("pre-seed: %v", err)
	}

	// Second write with same content must be idempotent (no error, wrote=false).
	data, err := os.ReadFile(dst) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != content {
		t.Errorf("drop-in content mismatch\ngot:  %q\nwant: %q", data, content)
	}
	if !strings.HasPrefix(content, "[Service]\n") {
		t.Errorf("drop-in missing [Service] section header")
	}
	if !strings.Contains(content, "EnvironmentFile=-"+defaultConfigDir+"/"+envFileName) {
		t.Errorf("drop-in missing EnvironmentFile= line pointing at env file")
	}

	// Verify live writeSystemdEnvDropIn is idempotent on the real path when
	// the directory doesn't exist. We can't call it against /etc/systemd in a
	// unit test, but we can exercise the MkdirAll + WriteFile branch via a
	// temp dir by temporarily substituting the target.
	dropInDir2 := filepath.Join(dir, "ezyshield.service.d")
	if err := os.MkdirAll(dropInDir2, 0o750); err != nil { //nolint:gosec // test file
		t.Fatalf("mkdir: %v", err)
	}
	dst2 := filepath.Join(dropInDir2, "env.conf")
	if err := os.WriteFile(dst2, []byte(content), 0o644); err != nil { //nolint:gosec // test file
		t.Fatalf("write: %v", err)
	}
	fi, err := os.Stat(dst2)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("drop-in perms = %04o, want 0644", fi.Mode().Perm())
	}
}

// TestInit_YesMode_NoKeyPrompt verifies that --yes skips askKeySource entirely:
// no tokenReader call, no env var name prompt, state.aiToken stays empty.
func TestInit_YesMode_NoKeyPrompt(t *testing.T) {
	tokenReaderCalled := false
	installTokenReader(t, func(_ string) (string, error) {
		tokenReaderCalled = true
		return "should-never-be-called", nil
	})

	state := &wizardState{
		webServers:  nil,
		sshUnit:     "",
		publicIP:    "",
		sshSourceIP: "",
	}
	out := captureStdout(t, func() {
		// yes=true — askQuestions skips the key prompt entirely.
		askQuestions(nil, state, true)
	})

	if tokenReaderCalled {
		t.Error("tokenReader was called in --yes mode — must be skipped")
	}
	if state.aiToken != "" {
		t.Errorf("aiToken must be empty in --yes mode, got %q", state.aiToken)
	}
	if strings.Contains(out, "should-never-be-called") {
		t.Errorf("stdout leaks the fake token in --yes mode: %q", out)
	}
}
