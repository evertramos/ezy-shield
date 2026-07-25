package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// stubDetection makes the environment-detection pass hermetic: the public-IP
// fetch (the only network call) is stubbed to "" so tests never touch the
// network, and the global jsonOutput flag is restored afterwards. The other
// detectors (nft, docker, systemctl) are exec calls that fail fast when the
// tool is absent, so they need no stub.
func stubDetection(t *testing.T) {
	t.Helper()
	origIP := detectPublicIP
	origJSON := jsonOutput
	detectPublicIP = func() string { return "" }
	t.Cleanup(func() {
		detectPublicIP = origIP
		jsonOutput = origJSON
	})
}

// runInit executes `ezyshield init <args...>` through the real root command
// (so flag wiring, including the persistent --json, is exercised) and returns
// stdout, stderr, and the command error.
func runInit(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := newRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(append([]string{"init"}, args...))
	err = root.Execute()
	return out.String(), errb.String(), err
}

// writeAnswers writes content to a temp answers file and returns its path.
func writeAnswers(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "answers.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("writing answers file: %v", err)
	}
	return p
}

// TestNonInteractive_FullRun_ValidConfig drives a complete answers file through
// init and asserts the generated config + policy load and validate, carry the
// right values, keep armed false, reference secrets only by env var, and stub
// the .env at mode 0600.
func TestNonInteractive_FullRun_ValidConfig(t *testing.T) {
	stubDetection(t)
	etc := filepath.Join(t.TempDir(), "etc")

	answers := writeAnswers(t, `
collectors:
  ssh: true
  web:
    - kind: file
      path: /var/log/nginx/access.log
      parser: nginx
allowlist:
  admin_ips: [203.0.113.4, 10.0.0.0/24]
ai:
  enabled: true
  provider: anthropic
  api_key_env: ANTHROPIC_API_KEY
enforce:
  cloudflare:
    - name: main
      mode: lists
      account_id: 0123456789abcdef0123456789abcdef
      api_token_env: CLOUDFLARE_API_TOKEN
`)

	_, _, err := runInit(t, "--answers", answers, "--config-dir", etc)
	if err != nil {
		t.Fatalf("non-interactive init failed: %v", err)
	}

	// Config must load through the strict loader.
	cfg, err := config.LoadConfig(filepath.Join(etc, "config.yaml"))
	if err != nil {
		t.Fatalf("generated config.yaml did not validate: %v", err)
	}
	if cfg.AI == nil || cfg.AI.Provider != "anthropic" {
		t.Fatalf("ai provider not set: %+v", cfg.AI)
	}
	if cfg.AI.APIKey != "env:ANTHROPIC_API_KEY" {
		t.Errorf("ai.api_key = %q, want env:ANTHROPIC_API_KEY", cfg.AI.APIKey)
	}
	if cfg.Enforce == nil || len(cfg.Enforce.Cloudflare) != 1 || cfg.Enforce.Cloudflare[0].Name != "main" {
		t.Fatalf("cloudflare account not set: %+v", cfg.Enforce)
	}
	if cfg.Enforce.Cloudflare[0].APIToken != "env:CLOUDFLARE_API_TOKEN" {
		t.Errorf("cloudflare api_token = %q, want env:CLOUDFLARE_API_TOKEN", cfg.Enforce.Cloudflare[0].APIToken)
	}
	var haveSSH, haveNginx bool
	for _, c := range cfg.Collectors {
		if c.Kind == "journald" {
			haveSSH = true
		}
		if c.Kind == "file" && c.Parser == "nginx" {
			haveNginx = true
		}
	}
	if !haveSSH || !haveNginx {
		t.Errorf("collectors missing ssh=%v nginx=%v: %+v", haveSSH, haveNginx, cfg.Collectors)
	}

	// Policy must load and be dry-run with the admin CIDRs.
	pol, err := config.LoadPolicy(filepath.Join(etc, "policy.yaml"))
	if err != nil {
		t.Fatalf("generated policy.yaml did not validate: %v", err)
	}
	if pol.Armed {
		t.Error("generated policy is armed — non-interactive init must always be dry-run (Hard Rule 1)")
	}
	if got := strings.Join(pol.AdminCIDRs, ","); !strings.Contains(got, "203.0.113.4/32") || !strings.Contains(got, "10.0.0.0/24") {
		t.Errorf("admin_cidrs = %v, want the two supplied entries", pol.AdminCIDRs)
	}

	// .env stubbed at 0600 with placeholders and NO real secret.
	envPath := filepath.Join(etc, ".env")
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat .env: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf(".env perms = %04o, want 0600", info.Mode().Perm())
	}
	env, _ := os.ReadFile(envPath) //nolint:errcheck // test path
	for _, name := range []string{"ANTHROPIC_API_KEY", "CLOUDFLARE_API_TOKEN"} {
		if !strings.Contains(string(env), name+"="+config.PlaceholderAPIKey) {
			t.Errorf(".env missing placeholder for %s; body=%q", name, string(env))
		}
	}
}

// TestNonInteractive_MissingAnswers_ListsAll asserts a single error enumerates
// every missing/invalid answer (not one-per-run) and nothing is written.
func TestNonInteractive_MissingAnswers_ListsAll(t *testing.T) {
	stubDetection(t)
	etc := filepath.Join(t.TempDir(), "etc")
	answers := writeAnswers(t, `
ai:
  enabled: true
enforce:
  cloudflare:
    - mode: lists
    - mode: rulesets
`)
	_, _, err := runInit(t, "--answers", answers, "--config-dir", etc)
	if err == nil {
		t.Fatal("expected an error for missing answers, got nil")
	}
	want := []string{
		"ai.provider is required",
		"enforce.cloudflare[0]: 'account_id' is required",
		"enforce.cloudflare[1]: 'zone_ids' is required",
		"enforce.cloudflare[0]: 'name' is required",
		"enforce.cloudflare[1]: 'name' is required",
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error missing %q\nfull error: %v", w, err)
		}
	}
	if _, statErr := os.Stat(etc); statErr == nil {
		t.Error("config dir was created despite validation failure — nothing must be written")
	}
}

// TestNonInteractive_SecretRejected covers Hard Rule 3: a literal secret via a
// flag or in the answers file is rejected with a pointed message, and nothing
// is written.
func TestNonInteractive_SecretRejected(t *testing.T) {
	const fakeKey = "sk-ant-secretpasted1234567890" //nolint:gosec // G101: intentional fake

	tests := []struct {
		name    string
		args    []string
		answers string
		wantMsg string
	}{
		{
			name:    "key as --ai-key-env flag",
			args:    []string{"-n", "--enable-ai", "--ai-provider", "anthropic", "--ai-key-env", fakeKey},
			wantMsg: "looks like an API key",
		},
		{
			name:    "ai.api_key literal in file",
			answers: "ai:\n  enabled: true\n  provider: anthropic\n  api_key: " + fakeKey + "\n",
			wantMsg: "ai.api_key is not accepted",
		},
		{
			name: "cloudflare api_token literal in file",
			answers: "enforce:\n  cloudflare:\n    - name: main\n      mode: lists\n" +
				"      account_id: 0123456789abcdef0123456789abcdef\n      api_token: " + fakeKey + "\n",
			wantMsg: "api_token is not accepted",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stubDetection(t)
			etc := filepath.Join(t.TempDir(), "etc")
			args := append([]string{}, tc.args...)
			if tc.answers != "" {
				args = append(args, "--answers", writeAnswers(t, tc.answers))
			}
			args = append(args, "--config-dir", etc)

			out, errOut, err := runInit(t, args...)
			if err == nil {
				t.Fatal("expected rejection, got nil error")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantMsg)
			}
			// The raw key must never be echoed anywhere.
			for _, s := range []string{err.Error(), out, errOut} {
				if strings.Contains(s, fakeKey) {
					t.Errorf("output leaks the raw secret: %q", s)
				}
			}
			if _, statErr := os.Stat(etc); statErr == nil {
				t.Error("config dir created despite secret rejection — nothing must be written")
			}
		})
	}
}

// TestNonInteractive_UnknownKey asserts strict decoding rejects a typo and
// names the offending field.
func TestNonInteractive_UnknownKey(t *testing.T) {
	stubDetection(t)
	etc := filepath.Join(t.TempDir(), "etc")
	answers := writeAnswers(t, "collectors:\n  sshh: true\n")
	_, _, err := runInit(t, "--answers", answers, "--config-dir", etc)
	if err == nil {
		t.Fatal("expected an error for the unknown key, got nil")
	}
	if !strings.Contains(err.Error(), "sshh") {
		t.Errorf("error should name the offending field 'sshh'; got %v", err)
	}
}

// TestNonInteractive_IdempotencyRefusesWithoutForce asserts a re-run refuses
// without --force and succeeds with it, matching interactive semantics.
func TestNonInteractive_IdempotencyRefusesWithoutForce(t *testing.T) {
	stubDetection(t)
	etc := filepath.Join(t.TempDir(), "etc")

	if _, _, err := runInit(t, "-n", "--config-dir", etc); err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	_, _, err := runInit(t, "-n", "--config-dir", etc)
	if err == nil {
		t.Fatal("re-run without --force must refuse, got nil error")
	}
	if !strings.Contains(err.Error(), "already exist") || !strings.Contains(err.Error(), "--force") {
		t.Errorf("refusal message should mention the conflict and --force; got %v", err)
	}
	if _, _, err := runInit(t, "-n", "--config-dir", etc, "--force"); err != nil {
		t.Errorf("re-run with --force must succeed, got %v", err)
	}
}

// TestNonInteractive_ForcePreservesRealSecret asserts a --force re-run keeps an
// operator-supplied real token in .env instead of overwriting it with the
// placeholder (idempotent secret handling).
func TestNonInteractive_ForcePreservesRealSecret(t *testing.T) {
	stubDetection(t)
	etc := filepath.Join(t.TempDir(), "etc")
	answers := writeAnswers(t, "ai:\n  enabled: true\n  provider: anthropic\n")

	if _, _, err := runInit(t, "--answers", answers, "--config-dir", etc); err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	const realKey = "sk-ant-REAL-operator-key-000" //nolint:gosec // G101: intentional fake
	envPath := filepath.Join(etc, ".env")
	body, _ := os.ReadFile(envPath) //nolint:errcheck // test path
	updated := strings.Replace(string(body), "ANTHROPIC_API_KEY="+config.PlaceholderAPIKey,
		"ANTHROPIC_API_KEY="+realKey, 1)
	if err := os.WriteFile(envPath, []byte(updated), 0o600); err != nil {
		t.Fatalf("seeding real key: %v", err)
	}

	if _, _, err := runInit(t, "--answers", answers, "--config-dir", etc, "--force"); err != nil {
		t.Fatalf("force re-run failed: %v", err)
	}
	got, _ := os.ReadFile(envPath) //nolint:errcheck // test path
	if !strings.Contains(string(got), "ANTHROPIC_API_KEY="+realKey) {
		t.Errorf("real key was clobbered on --force re-run; body=%q", string(got))
	}
	if strings.Contains(string(got), config.PlaceholderAPIKey) {
		t.Errorf("re-run replaced the real key with the placeholder; body=%q", string(got))
	}
}

// TestNonInteractive_JSONParses asserts --json emits a parseable summary on
// stdout (progress on stderr), always dry-run.
func TestNonInteractive_JSONParses(t *testing.T) {
	stubDetection(t)
	etc := filepath.Join(t.TempDir(), "etc")

	stdout, _, err := runInit(t, "-n", "--config-dir", etc, "--json")
	if err != nil {
		t.Fatalf("non-interactive init --json failed: %v", err)
	}
	var summary initJSONSummary
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout=%q", err, stdout)
	}
	if summary.Armed {
		t.Error("json summary reports armed=true; must be false")
	}
	if len(summary.NextSteps) == 0 {
		t.Error("json summary has no next_steps")
	}
	if len(summary.Files) == 0 {
		t.Error("json summary lists no files")
	}
}

// TestNonInteractive_FlagsOverrideFile asserts a flag overrides the same key
// from the answers file.
func TestNonInteractive_FlagsOverrideFile(t *testing.T) {
	stubDetection(t)
	etc := filepath.Join(t.TempDir(), "etc")
	// File disables SSH; flag re-enables it.
	answers := writeAnswers(t, "collectors:\n  ssh: false\n")

	if _, _, err := runInit(t, "--answers", answers, "--config-dir", etc, "--monitor-ssh"); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	cfg, err := config.LoadConfig(filepath.Join(etc, "config.yaml"))
	if err != nil {
		t.Fatalf("config did not validate: %v", err)
	}
	var haveSSH bool
	for _, c := range cfg.Collectors {
		if c.Kind == "journald" {
			haveSSH = true
		}
	}
	if !haveSSH {
		t.Errorf("--monitor-ssh flag did not override collectors.ssh:false; collectors=%+v", cfg.Collectors)
	}
}

// TestNonInteractive_YesConflict asserts --yes and --non-interactive are
// mutually exclusive.
func TestNonInteractive_YesConflict(t *testing.T) {
	stubDetection(t)
	etc := filepath.Join(t.TempDir(), "etc")
	_, _, err := runInit(t, "-n", "--yes", "--config-dir", etc)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected a mutual-exclusion error, got %v", err)
	}
}

// TestEnsureEnvPlaceholders_Idempotent unit-tests the .env merge: fresh write,
// then a no-op re-run, then real-value preservation.
func TestEnsureEnvPlaceholders_Idempotent(t *testing.T) {
	dir := t.TempDir()
	names := []string{"ANTHROPIC_API_KEY", "CLOUDFLARE_API_TOKEN"}

	touched, err := ensureEnvPlaceholders(dir, names)
	if err != nil || !touched {
		t.Fatalf("first call: touched=%v err=%v, want touched=true", touched, err)
	}
	// Second call with the same placeholders must be a no-op.
	touched, err = ensureEnvPlaceholders(dir, names)
	if err != nil || touched {
		t.Fatalf("second call: touched=%v err=%v, want touched=false (idempotent)", touched, err)
	}
	// A real value must survive.
	envPath := filepath.Join(dir, envFileName)
	body, _ := os.ReadFile(envPath) //nolint:errcheck // test path
	const real = "sk-ant-real-value-123" //nolint:gosec // G101: intentional fake
	seeded := strings.Replace(string(body), "ANTHROPIC_API_KEY="+config.PlaceholderAPIKey,
		"ANTHROPIC_API_KEY="+real, 1)
	if err := os.WriteFile(envPath, []byte(seeded), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureEnvPlaceholders(dir, names); err != nil {
		t.Fatalf("third call: %v", err)
	}
	got, _ := os.ReadFile(envPath) //nolint:errcheck // test path
	if !strings.Contains(string(got), "ANTHROPIC_API_KEY="+real) {
		t.Errorf("real value clobbered; body=%q", string(got))
	}
}

// TestValidateAnswers_TableDriven exercises the collect-all-problems validator
// directly for precise per-field coverage.
func TestValidateAnswers_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		answers  initAnswers
		wantNone bool
		wantSub  string
	}{
		{
			name:     "empty is valid",
			answers:  initAnswers{},
			wantNone: true,
		},
		{
			name:    "ai enabled without provider",
			answers: initAnswers{AI: answersAI{Enabled: true}},
			wantSub: "ai.provider is required",
		},
		{
			name:    "ai unknown provider",
			answers: initAnswers{AI: answersAI{Enabled: true, Provider: "acme"}},
			wantSub: `ai.provider "acme" is unknown`,
		},
		{
			name: "web file without path",
			answers: initAnswers{Collectors: answersCollectors{
				Web: []answersWebCollector{{Kind: "file", Parser: "nginx"}}}},
			wantSub: "kind 'file' requires 'path'",
		},
		{
			name: "web without parser",
			answers: initAnswers{Collectors: answersCollectors{
				Web: []answersWebCollector{{Kind: "docker", Container: "web"}}}},
			wantSub: "'parser' is required",
		},
		{
			name: "admin ip invalid",
			answers: initAnswers{Allowlist: answersAllowlist{
				AdminIPs: []string{"not-an-ip"}}},
			wantSub: "is not a valid IP or CIDR",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validateAnswers(&tc.answers)
			if tc.wantNone {
				if len(got) != 0 {
					t.Fatalf("expected no problems, got %v", got)
				}
				return
			}
			joined := strings.Join(got, "\n")
			if !strings.Contains(joined, tc.wantSub) {
				t.Errorf("problems %v do not contain %q", got, tc.wantSub)
			}
		})
	}
}
