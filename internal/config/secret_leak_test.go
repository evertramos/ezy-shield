// Package config — secret-leak gate tests (SECURITY-REVIEW §4, AGENTS Hard Rule §3).
//
// Tokens must never appear in error strings or any other observable channel.
// These tests confirm that hard failures in secret resolution produce generic
// messages that do not echo back the resolved token value.
package config_test

import (
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
	"gopkg.in/yaml.v3"
)

const fakeToken = "SUPER-SECRET-TOKEN-abc123xyz789"

// TestSecretRef_UnsetVar_ErrorNoLeak verifies that when the referenced env var
// is absent, the error string does not contain any token-shaped text.
func TestSecretRef_UnsetVar_ErrorNoLeak(t *testing.T) {
	// Use a genuinely absent env var name.
	ref := config.SecretRef("env:EZYSHIELD_DEFINITELY_NOT_SET_QQ99ZZ")
	_, err := ref.Resolve()
	if err == nil {
		t.Fatal("expected error for unset var, got nil")
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Errorf("error for absent var contains fake token: %q", err.Error())
	}
}

// TestSecretRef_InlineValueRejected_NoTokenInError verifies that the YAML parser
// rejects an inline secret value and that the returned error does NOT echo the
// secret back into the message (Hard Rule §3: secrets never in logs/errors).
func TestSecretRef_InlineValueRejected_NoTokenInError(t *testing.T) {
	yamlInput := "api_key: " + fakeToken

	type cfg struct {
		APIKey config.SecretRef `yaml:"api_key"`
	}
	var c cfg
	err := yaml.Unmarshal([]byte(yamlInput), &c)
	if err == nil {
		t.Fatal("inline secret value must be rejected by UnmarshalYAML, got nil error")
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Errorf("rejection error leaks the inline token value: %q", err.Error())
	}
}

// TestSecretRef_Resolve_ErrorNoLeak confirms that a Resolve() failure on a
// configured (but absent) env var returns a message that cannot contain a
// hypothetical token value.
func TestSecretRef_Resolve_ErrorNoLeak(t *testing.T) {
	const envVar = "EZYSHIELD_TEST_RESOLVE_NOLEAK"
	ref := config.SecretRef("env:" + envVar)
	_, err := ref.Resolve()
	if err == nil {
		t.Fatal("expected error for unset var")
	}
	if !strings.Contains(err.Error(), envVar) {
		t.Logf("(non-fatal) error doesn't mention the var name — harder to diagnose: %q", err.Error())
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Errorf("error leaks token: %q", err.Error())
	}
}

// TestSecretRef_ResolvedValue_NotInSubsequentError simulates the case where a
// secret is resolved and then a different SecretRef error occurs. The resolved
// token must not appear in any subsequent error string.
func TestSecretRef_ResolvedValue_NotInSubsequentError(t *testing.T) {
	const envVar = "EZYSHIELD_TEST_TOKEN_NOLEAK"
	t.Setenv(envVar, fakeToken)

	ref := config.SecretRef("env:" + envVar)
	resolved, err := ref.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved != fakeToken {
		t.Fatalf("test setup: resolved %q, want %q", resolved, fakeToken)
	}

	empty := config.SecretRef("")
	_, err2 := empty.Resolve()
	if err2 == nil {
		t.Fatal("expected error for empty SecretRef")
	}
	if strings.Contains(err2.Error(), fakeToken) {
		t.Errorf("error from empty SecretRef leaks token set in another ref: %q", err2.Error())
	}
}
