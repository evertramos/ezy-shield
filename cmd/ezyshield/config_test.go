package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// showConfig exercises every secret-bearing shape `config show` can meet:
// SecretRef fields (env: references) and raw webhook header values.
const showConfig = `
data_dir: /var/lib/ezyshield
collectors:
  - kind: journald
    unit: sshd
enforce:
  cloudflare:
    api_token: env:EZY_TEST_CF_TOKEN
    mode: lists
    account_id: 0123456789abcdef0123456789abcdef
ai:
  provider: anthropic
  api_key: env:EZY_TEST_AI_KEY
notify:
  webhook:
    url: env:EZY_TEST_WH_URL
    headers:
      Authorization: Bearer raw-header-secret-do-not-print
`

// TestRunConfigShow_RedactsSecrets is the §4 gate for `config show`: with
// real token values present in the environment, neither the resolved values
// nor raw webhook header values may reach the output — while the env:NAME
// references stay visible so the operator can act on them.
func TestRunConfigShow_RedactsSecrets(t *testing.T) {
	const resolved = "resolved-secret-value-XYZZY"
	t.Setenv("EZY_TEST_CF_TOKEN", resolved)
	t.Setenv("EZY_TEST_AI_KEY", resolved)
	t.Setenv("EZY_TEST_WH_URL", resolved)

	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", showConfig)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var out, errOut bytes.Buffer
	code := runConfigShow(&out, &errOut, cfg, pol, false)
	if code != validateExitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, validateExitOK, errOut.String())
	}

	got := out.String()
	for _, leak := range []string{resolved, "raw-header-secret-do-not-print"} {
		if strings.Contains(got, leak) {
			t.Errorf("output leaks secret %q:\n%s", leak, got)
		}
	}
	for _, want := range []string{
		"env:EZY_TEST_CF_TOKEN",
		"env:EZY_TEST_AI_KEY",
		"<redacted>",
		"Authorization:",
		"armed: false",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// TestRunConfigShow_JSON checks the JSON form: valid JSON, YAML-tag field
// names, and the same redaction guarantees as the YAML form.
func TestRunConfigShow_JSON(t *testing.T) {
	const resolved = "resolved-secret-value-XYZZY"
	t.Setenv("EZY_TEST_CF_TOKEN", resolved)
	t.Setenv("EZY_TEST_AI_KEY", resolved)
	t.Setenv("EZY_TEST_WH_URL", resolved)

	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", showConfig)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var out, errOut bytes.Buffer
	code := runConfigShow(&out, &errOut, cfg, pol, true)
	if code != validateExitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, validateExitOK, errOut.String())
	}

	raw := out.String()
	if strings.Contains(raw, resolved) || strings.Contains(raw, "raw-header-secret-do-not-print") {
		t.Errorf("JSON output leaks a secret:\n%s", raw)
	}

	var doc struct {
		Config map[string]any `json:"config"`
		Policy map[string]any `json:"policy"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, raw)
	}
	if doc.Config["data_dir"] != "/var/lib/ezyshield" {
		t.Errorf("config.data_dir = %v, want /var/lib/ezyshield (yaml field names expected)",
			doc.Config["data_dir"])
	}
	if doc.Policy["ban_threshold"] != float64(70) {
		t.Errorf("policy.ban_threshold = %v, want 70", doc.Policy["ban_threshold"])
	}
}

func TestRunConfigShow_MissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var out, errOut bytes.Buffer
	code := runConfigShow(&out, &errOut, filepath.Join(dir, "absent.yaml"), pol, false)
	if code != validateExitNotFound {
		t.Errorf("exit code = %d, want %d", code, validateExitNotFound)
	}
	if !strings.Contains(errOut.String(), "file not found") {
		t.Errorf("stderr missing 'file not found': %s", errOut.String())
	}
}

func TestRunConfigShow_InvalidConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", "data_dir: /d\nbogus_key: true\n")
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var out, errOut bytes.Buffer
	code := runConfigShow(&out, &errOut, cfg, pol, false)
	if code != validateExitError {
		t.Errorf("exit code = %d, want %d", code, validateExitError)
	}
	if errOut.Len() == 0 {
		t.Error("expected an error message on stderr")
	}
}

// TestRunConfigShow_YAMLRoundTrips feeds the rendered documents back through
// the strict loaders: the effective view must itself be a valid config.
func TestRunConfigShow_YAMLRoundTrips(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", validConfig)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var out, errOut bytes.Buffer
	if code := runConfigShow(&out, &errOut, cfg, pol, false); code != validateExitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, errOut.String())
	}

	docs := strings.SplitN(out.String(), "\n---\n", 2)
	if len(docs) != 2 {
		t.Fatalf("expected two YAML documents separated by ---, got:\n%s", out.String())
	}
	cfgPath := writeFile(t, dir, "roundtrip-config.yaml", docs[0])
	polPath := writeFile(t, dir, "roundtrip-policy.yaml", docs[1])

	var buf bytes.Buffer
	if code := runValidate(&buf, cfgPath, polPath); code != validateExitOK {
		t.Errorf("re-validating rendered output failed (code %d):\n%s", code, buf.String())
	}
}

// TestConfigValidate_GroupAndAlias runs both spellings through the real
// command tree and expects identical validation results.
func TestConfigValidate_GroupAndAlias(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", validConfig)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	for _, args := range [][]string{
		{"config", "validate", "--config", cfg, "--policy", pol},
		{"validate", "--config", cfg, "--policy", pol},
	} {
		var out bytes.Buffer
		root := newRootCmd()
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Errorf("%v: unexpected error: %v", args, err)
		}
		if !strings.Contains(out.String(), "Result: 0 error(s)") {
			t.Errorf("%v: expected '0 error(s)', got:\n%s", args, out.String())
		}
	}
}
