package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile writes content to dir/name at 0o640 for test setup.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	//nolint:gosec // test file, intentional 0640 permission
	if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

const validConfig = `
data_dir: /var/lib/ezyshield
collectors:
  - kind: journald
    unit: sshd
`

const validPolicy = `
armed: false
ban_threshold: 70
observe_threshold: 40
max_bans_per_minute: 30
strikes:
  - ttl: 5m
  - ttl: 1h
  - ttl: 24h
  - ttl: 168h
  - ttl: 0
allowlist:
  - 127.0.0.1/32
`

func TestRunValidate_AllValid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", validConfig)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, pol)
	if code != validateExitOK {
		t.Errorf("exit code = %d, want %d (output: %s)", code, validateExitOK, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "Result: 0 error(s)") {
		t.Errorf("expected '0 error(s)' in summary, got: %s", out)
	}
}

func TestRunValidate_MissingConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var buf bytes.Buffer
	code := runValidate(&buf, filepath.Join(dir, "absent.yaml"), pol)
	if code != validateExitNotFound {
		t.Errorf("exit code = %d, want %d", code, validateExitNotFound)
	}
	if !strings.Contains(buf.String(), "file not found") {
		t.Errorf("expected 'file not found' in output, got: %s", buf.String())
	}
}

func TestRunValidate_MissingPolicy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", validConfig)

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, filepath.Join(dir, "absent.yaml"))
	if code != validateExitNotFound {
		t.Errorf("exit code = %d, want %d", code, validateExitNotFound)
	}
}

func TestRunValidate_BothMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var buf bytes.Buffer
	code := runValidate(&buf, filepath.Join(dir, "c.yaml"), filepath.Join(dir, "p.yaml"))
	if code != validateExitNotFound {
		t.Errorf("exit code = %d, want %d", code, validateExitNotFound)
	}
}

func TestRunValidate_UnknownConfigField(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", "data_dir: /tmp\ncolectors: []\n")
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, pol)
	if code != validateExitError {
		t.Errorf("exit code = %d, want %d", code, validateExitError)
	}
	out := buf.String()
	// yaml.v3 error should mention the unknown field with the typo.
	if !strings.Contains(out, "colectors") {
		t.Errorf("expected unknown field name in error, got: %s", out)
	}
}

func TestRunValidate_InvalidCollectorParser(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", `
data_dir: /tmp
collectors:
  - kind: docker
    container: webapp
    parser: ngix
`)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, pol)
	if code != validateExitError {
		t.Errorf("exit code = %d, want %d", code, validateExitError)
	}
	out := buf.String()
	if !strings.Contains(out, "invalid parser") {
		t.Errorf("expected 'invalid parser' error, got: %s", out)
	}
	// YAML syntax should still report PASS since decode succeeded.
	if !strings.Contains(out, "✓ YAML syntax") {
		t.Errorf("YAML syntax should pass when only validation fails, got: %s", out)
	}
}

func TestRunValidate_MissingDataDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", `
collectors:
  - kind: journald
    unit: sshd
`)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, pol)
	if code != validateExitError {
		t.Errorf("exit code = %d, want %d", code, validateExitError)
	}
	if !strings.Contains(buf.String(), "data_dir is required") {
		t.Errorf("expected 'data_dir is required', got: %s", buf.String())
	}
}

func TestRunValidate_NoCollectors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", "data_dir: /tmp\n")
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, pol)
	if code != validateExitError {
		t.Errorf("exit code = %d, want %d", code, validateExitError)
	}
	if !strings.Contains(buf.String(), "at least one collector") {
		t.Errorf("expected collector requirement error, got: %s", buf.String())
	}
}

func TestRunValidate_FileCollectorPathWarning(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", `
data_dir: /tmp
collectors:
  - kind: file
    path: /definitely/not/a/real/log/file.log
`)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, pol)
	if code != validateExitOK {
		t.Errorf("exit code = %d, want %d (warnings shouldn't fail)", code, validateExitOK)
	}
	out := buf.String()
	if !strings.Contains(out, "not readable") {
		t.Errorf("expected 'not readable' warning, got: %s", out)
	}
	if !strings.Contains(out, "1 warning") {
		t.Errorf("expected 1 warning in summary, got: %s", out)
	}
}

func TestRunValidate_EnvVarWarning(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", `
data_dir: /tmp
collectors:
  - kind: journald
    unit: sshd
ai:
  provider: anthropic
  api_key: env:EZYSHIELD_VALIDATE_TEST_NOT_SET_XYZ
  ambiguous_band: [30, 75]
`)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, pol)
	if code != validateExitOK {
		t.Errorf("exit code = %d, want %d (env warning shouldn't fail)", code, validateExitOK)
	}
	out := buf.String()
	if !strings.Contains(out, "EZYSHIELD_VALIDATE_TEST_NOT_SET_XYZ") {
		t.Errorf("expected env var name in warning, got: %s", out)
	}
	if !strings.Contains(out, "ai.api_key") {
		t.Errorf("expected field name in warning, got: %s", out)
	}
}

func TestRunValidate_EnvVarSet_NoWarning(t *testing.T) {
	t.Setenv("EZYSHIELD_VALIDATE_TEST_IS_SET", "x")
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", `
data_dir: /tmp
collectors:
  - kind: journald
    unit: sshd
ai:
  provider: anthropic
  api_key: env:EZYSHIELD_VALIDATE_TEST_IS_SET
  ambiguous_band: [30, 75]
`)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, pol)
	if code != validateExitOK {
		t.Errorf("exit code = %d, want %d", code, validateExitOK)
	}
	if strings.Contains(buf.String(), "EZYSHIELD_VALIDATE_TEST_IS_SET") {
		t.Errorf("env var should not appear in output when set, got: %s", buf.String())
	}
}

func TestRunValidate_SecretNeverLeaks(t *testing.T) {
	// Regression guard for SECURITY-REVIEW §4 / Hard Rule §3: the resolved
	// token must never appear in the validate output.
	const tokenValue = "SUPER-SECRET-DO-NOT-LEAK-123"
	t.Setenv("EZYSHIELD_VALIDATE_LEAK_TEST", tokenValue)

	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", `
data_dir: /tmp
collectors:
  - kind: journald
    unit: sshd
ai:
  provider: anthropic
  api_key: env:EZYSHIELD_VALIDATE_LEAK_TEST
  ambiguous_band: [30, 75]
`)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var buf bytes.Buffer
	_ = runValidate(&buf, cfg, pol)
	if strings.Contains(buf.String(), tokenValue) {
		t.Errorf("validate output leaks secret value: %s", buf.String())
	}
}

func TestRunValidate_StrikesNotMonotonic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", validConfig)
	pol := writeFile(t, dir, "policy.yaml", `
armed: false
strikes:
  - ttl: 1h
  - ttl: 5m
`)

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, pol)
	if code != validateExitError {
		t.Errorf("exit code = %d, want %d", code, validateExitError)
	}
	if !strings.Contains(buf.String(), "must be greater than previous") {
		t.Errorf("expected monotonic error, got: %s", buf.String())
	}
}

func TestRunValidate_StrikesPermanentNotLast(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", validConfig)
	pol := writeFile(t, dir, "policy.yaml", `
armed: false
strikes:
  - ttl: 0
  - ttl: 5m
`)

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, pol)
	if code != validateExitError {
		t.Errorf("exit code = %d, want %d", code, validateExitError)
	}
	if !strings.Contains(buf.String(), "permanent entry") {
		t.Errorf("expected 'permanent entry' error, got: %s", buf.String())
	}
}

func TestRunValidate_PolicyInvalidYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", validConfig)
	pol := writeFile(t, dir, "policy.yaml", "armed: [oops\n")

	var buf bytes.Buffer
	code := runValidate(&buf, cfg, pol)
	if code != validateExitError {
		t.Errorf("exit code = %d, want %d", code, validateExitError)
	}
	if !strings.Contains(buf.String(), "YAML syntax") {
		t.Errorf("expected YAML syntax error, got: %s", buf.String())
	}
}

func TestRunValidate_CrossValidationSection(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", validConfig)
	pol := writeFile(t, dir, "policy.yaml", validPolicy)

	var buf bytes.Buffer
	_ = runValidate(&buf, cfg, pol)
	if !strings.Contains(buf.String(), "cross-validation:") {
		t.Errorf("expected cross-validation section, got: %s", buf.String())
	}
}

func TestStrikesMonotonic_PermanentOnlyAtEnd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.yaml", validConfig)
	pol := writeFile(t, dir, "policy.yaml", `
armed: false
strikes:
  - ttl: 5m
  - ttl: 1h
  - ttl: 0
`)
	var buf bytes.Buffer
	if code := runValidate(&buf, cfg, pol); code != validateExitOK {
		t.Errorf("expected OK with permanent-last, got %d (out: %s)", code, buf.String())
	}
}

func TestValidateCmd_FlagsRegistered(t *testing.T) {
	t.Parallel()
	cmd := newValidateCmd()
	if cmd.Flags().Lookup("config") == nil {
		t.Error("--config flag missing")
	}
	if cmd.Flags().Lookup("policy") == nil {
		t.Error("--policy flag missing")
	}
}
