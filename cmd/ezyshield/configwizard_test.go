package main

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

const cfTestAccountID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// cfListsHappyDeps returns prompter answers + HTTP stubs for a successful
// lists-mode Cloudflare wizard run (mirrors TestRunCDNStep_HappyPath_Lists,
// minus the CDN-detection stage that config-mode skips).
func cfListsHappyDeps(token string) (*scriptedPrompter, cdnDeps) {
	prompt := &scriptedPrompter{
		strings: []string{
			"lists",             // mode
			"block",             // action
			cfTestAccountID,     // account_id
			"ezyshield_blocked", // list name
		},
	}
	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			"/accounts/" + cfTestAccountID + "/tokens/verify": {status: 200, bodyJSON: `{"success":true}`},
			"/accounts/" + cfTestAccountID + "/rules/lists":   {status: 200, bodyJSON: `{"success":true,"result":[]}`},
		},
	}
	return prompt, cdnDeps{
		HTTPClient:   httpc,
		TokenReader:  func(string) (string, error) { return token, nil },
		CFAPIBaseURL: "http://cf.example",
	}
}

// TestRunConfigComponent_CloudflareHappyPath drives `config enforcer
// cloudflare` end to end on an existing installation: entry merged, write
// atomic with .bak, token only in .env, secrets never on stdout.
func TestRunConfigComponent_CloudflareHappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml", validConfig)
	const token = "cf-test-token-secret" //nolint:gosec // G101: test fake, not a real credential
	prompt, deps := cfListsHappyDeps(token)

	out := captureStep(t, func(p *wPrinter) {
		code := runConfigComponent(context.Background(), p, prompt, deps,
			"enforcer", "cloudflare", cfgPath)
		if code != validateExitOK {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	// config.yaml: entry present, strict loader accepts it, token absent.
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("saved config does not load: %v", err)
	}
	if len(cfg.Enforce.Cloudflare) != 1 {
		t.Fatalf("cloudflare entries = %d, want 1", len(cfg.Enforce.Cloudflare))
	}
	cf := cfg.Enforce.Cloudflare[0]
	if cf.Mode != "lists" || cf.AccountID != cfTestAccountID || cf.ListName != "ezyshield_blocked" {
		t.Errorf("merged entry wrong: %+v", cf)
	}
	if string(cf.APIToken) != "env:CLOUDFLARE_API_TOKEN" {
		t.Errorf("api_token = %q, want env reference", string(cf.APIToken))
	}
	raw, _ := os.ReadFile(cfgPath) //nolint:gosec // test path
	if strings.Contains(string(raw), token) {
		t.Errorf("config.yaml contains the raw token:\n%s", raw)
	}
	// Pre-existing collector config survives the merge.
	if len(cfg.Collectors) != 1 || cfg.Collectors[0].Unit != "sshd" {
		t.Errorf("original collectors lost in merge: %+v", cfg.Collectors)
	}

	// Backup holds the pre-wizard content.
	bak, err := os.ReadFile(cfgPath + ".bak") //nolint:gosec // test path
	if err != nil {
		t.Fatalf("expected .bak: %v", err)
	}
	if string(bak) != validConfig {
		t.Errorf(".bak content differs from original")
	}

	// Token landed in .env (0600), and nowhere else.
	envPath := filepath.Join(dir, envFileName)
	envRaw, err := os.ReadFile(envPath) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("expected .env: %v", err)
	}
	if !strings.Contains(string(envRaw), "CLOUDFLARE_API_TOKEN="+token) {
		t.Errorf(".env missing token line:\n%s", envRaw)
	}
	if st, _ := os.Stat(envPath); st.Mode().Perm() != 0o600 {
		t.Errorf(".env mode = %o, want 0600", st.Mode().Perm())
	}

	// stdout: summary + hints, and never the token.
	if strings.Contains(out, token) {
		t.Errorf("stdout leaks the token: %q", out)
	}
	for _, want := range []string{"Changed keys:", "enforce.cloudflare", "added entry",
		"account_id = " + cfTestAccountID, "backup:", "config validate"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q:\n%s", want, out)
		}
	}
}

// TestRunConfigComponent_CloudflareReplacesExisting re-runs the wizard on a
// config that already has the (single, unnamed) cloudflare entry: the entry
// is replaced, not duplicated.
func TestRunConfigComponent_CloudflareReplacesExisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	existing := validConfig + `enforce:
  cloudflare:
    api_token: env:CLOUDFLARE_API_TOKEN
    mode: rulesets
    zone_ids:
      - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
`
	cfgPath := writeFile(t, dir, "config.yaml", existing)
	prompt, deps := cfListsHappyDeps("cf-rotated-token")

	out := captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, prompt, deps,
			"enforcer", "cloudflare", cfgPath); code != validateExitOK {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("saved config does not load: %v", err)
	}
	if len(cfg.Enforce.Cloudflare) != 1 {
		t.Fatalf("cloudflare entries = %d, want 1 (replace, not append)", len(cfg.Enforce.Cloudflare))
	}
	if cfg.Enforce.Cloudflare[0].Mode != "lists" {
		t.Errorf("mode = %q, want lists after replace", cfg.Enforce.Cloudflare[0].Mode)
	}
	if !strings.Contains(out, "replaced entry") {
		t.Errorf("summary should say 'replaced entry':\n%s", out)
	}
}

// TestRunConfigComponent_AbortLeavesEverythingUntouched covers the wizard
// abort path (no token pasted): config bytes identical, no .bak, no .env.
func TestRunConfigComponent_AbortLeavesEverythingUntouched(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml", validConfig)
	prompt := &scriptedPrompter{strings: []string{"lists", "block"}}
	deps := cdnDeps{
		TokenReader: func(string) (string, error) { return "", nil }, // ENTER = skip
	}

	out := captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, prompt, deps,
			"enforcer", "cloudflare", cfgPath); code != validateExitError {
			t.Errorf("exit code = %d, want %d", code, validateExitError)
		}
	})

	raw, _ := os.ReadFile(cfgPath) //nolint:gosec // test path
	if string(raw) != validConfig {
		t.Errorf("config.yaml modified on abort:\n%s", raw)
	}
	if _, err := os.Stat(cfgPath + ".bak"); !os.IsNotExist(err) {
		t.Errorf(".bak must not exist on abort (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, envFileName)); !os.IsNotExist(err) {
		t.Errorf(".env must not exist on abort (err=%v)", err)
	}
	for _, want := range []string{"Cloudflare enforcer setup did NOT complete", "No changes were made."} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q:\n%s", want, out)
		}
	}
}

// TestRunConfigComponent_UnknownNameAndKind: registry misses list what IS
// available instead of a bare failure.
func TestRunConfigComponent_UnknownNameAndKind(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml", validConfig)

	out := captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, &scriptedPrompter{}, cdnDeps{},
			"enforcer", "bunny", cfgPath); code != validateExitError {
			t.Errorf("exit code = %d, want %d", code, validateExitError)
		}
	})
	if !strings.Contains(out, `unknown enforcer "bunny"`) || !strings.Contains(out, "cloudflare") {
		t.Errorf("error should name the miss and list alternatives:\n%s", out)
	}

	if _, err := lookupComponentWizard("nonsense", "x"); err == nil ||
		!strings.Contains(err.Error(), "enforcer") {
		t.Errorf("unknown kind error should list available kinds, got: %v", err)
	}
}

// TestRunConfigComponent_MissingConfig: reconfiguring without an installed
// config points the operator at init.
func TestRunConfigComponent_MissingConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	out := captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, &scriptedPrompter{}, cdnDeps{},
			"enforcer", "cloudflare", filepath.Join(dir, "config.yaml")); code != validateExitNotFound {
			t.Errorf("exit code = %d, want %d", code, validateExitNotFound)
		}
	})
	if !strings.Contains(out, "run the init wizard first") {
		t.Errorf("missing-config hint absent:\n%s", out)
	}
}

// TestNewAskFuncs_YesModeAndDefaults covers the shared prompt closures the
// init wizard and config wizards both use.
func TestNewAskFuncs_YesModeAndDefaults(t *testing.T) {
	t.Parallel()

	// yes mode: defaults returned, nothing printed, nil scanner tolerated.
	var buf bytes.Buffer
	ask, askBool := newAskFuncs(nil, &buf, true)
	if got := ask("q", "dflt"); got != "dflt" {
		t.Errorf("yes-mode ask = %q, want default", got)
	}
	if !askBool("q", true) || askBool("q", false) {
		t.Error("yes-mode askBool must return the default")
	}
	if buf.Len() != 0 {
		t.Errorf("yes mode must not prompt, printed: %q", buf.String())
	}

	// interactive: typed answers win, blank falls back to default.
	in := strings.NewReader("answer\n\nyes\n\n")
	buf.Reset()
	ask, askBool = newAskFuncs(bufio.NewScanner(in), &buf, false)
	if got := ask("q1", "d1"); got != "answer" {
		t.Errorf("ask = %q, want typed answer", got)
	}
	if got := ask("q2", "d2"); got != "d2" {
		t.Errorf("blank line should return default, got %q", got)
	}
	if !askBool("q3", false) {
		t.Error(`"yes" should return true`)
	}
	if askBool("q4", false) {
		t.Error("blank line should return the (false) default")
	}
	if !strings.Contains(buf.String(), "q1 [d1]: ") {
		t.Errorf("prompt formatting changed: %q", buf.String())
	}
}
