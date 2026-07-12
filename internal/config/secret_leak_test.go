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

// fakePastedKey is an obviously-fake Anthropic-shaped string. Never a real
// credential. Represents the operator paste-mistake at the heart of issue #13:
// they pasted the secret where the wizard asked for the ENV VAR NAME, so
// config.yaml ended up with `api_key: env:sk-ant-fake-...`.
const fakePastedKey = "sk-ant-fake-1234567890123456789012345"

// TestSecretRef_MalformedEnvRef_RejectedAtLoad locks in the loader-side defense
// for issue #13: a hand-edited config that carries `env:<pasted-key>` must be
// rejected at YAML unmarshal time and the error message must NOT contain the
// pasted value.
func TestSecretRef_MalformedEnvRef_RejectedAtLoad(t *testing.T) {
	yamlInput := "api_key: env:" + fakePastedKey

	type cfg struct {
		APIKey config.SecretRef `yaml:"api_key"`
	}
	var c cfg
	err := yaml.Unmarshal([]byte(yamlInput), &c)
	if err == nil {
		t.Fatal("malformed env: reference must be rejected at load time")
	}
	if strings.Contains(err.Error(), fakePastedKey) {
		t.Errorf("load-time rejection leaks the pasted value verbatim: %q", err.Error())
	}
}

// TestSecretRef_MalformedEnvRef_ResolveRedacted covers the exact issue #13
// production symptom: the daemon reads config, sees `env:sk-ant-...`, calls
// Resolve(), and used to log `environment variable sk-ant-... is not set` —
// leaking the full key into journald on every restart. Post-fix, Resolve must
// reject the malformed reference BEFORE reaching os.LookupEnv, and the error
// must be redacted.
func TestSecretRef_MalformedEnvRef_ResolveRedacted(t *testing.T) {
	ref := config.SecretRef("env:" + fakePastedKey)
	_, err := ref.Resolve()
	if err == nil {
		t.Fatal("Resolve must reject a malformed env: reference")
	}
	if strings.Contains(err.Error(), fakePastedKey) {
		t.Errorf("Resolve error leaks pasted value verbatim (issue #13 regression): %q", err.Error())
	}
}

// TestSecretRef_LoadCleanEnvRef sanity-checks that a well-formed env:
// reference still loads without issue after the tightening.
func TestSecretRef_LoadCleanEnvRef(t *testing.T) {
	yamlInput := "api_key: env:ANTHROPIC_API_KEY"
	type cfg struct {
		APIKey config.SecretRef `yaml:"api_key"`
	}
	var c cfg
	if err := yaml.Unmarshal([]byte(yamlInput), &c); err != nil {
		t.Fatalf("clean env: reference must load, got: %v", err)
	}
	if string(c.APIKey) != "env:ANTHROPIC_API_KEY" {
		t.Errorf("APIKey = %q, want env:ANTHROPIC_API_KEY", string(c.APIKey))
	}
}

// TestNotifyChannels_InlineSecretRejected_NoLeak locks in that every
// secret-bearing notify-channel field (telegram bot_token, email password,
// slack/discord/webhook URLs) uses SecretRef semantics: an inline credential
// pasted into config.yaml is rejected at load time and the rejection error
// never echoes the value back (Hard Rule §3, SECURITY-REVIEW §4).
func TestNotifyChannels_InlineSecretRejected_NoLeak(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		yaml string
	}{
		{"telegram bot_token", "telegram:\n  bot_token: " + fakeToken + "\n  chat_ids: [\"1\"]\n"},
		{"email password", "email:\n  from: a@b\n  to: [c@d]\n  host: h\n  port: 587\n  password: " + fakeToken + "\n"},
		{"slack webhook_url", "slack:\n  webhook_url: https://hooks.slack.example/" + fakeToken + "\n"},
		{"discord webhook_url", "discord:\n  webhook_url: https://discord.example/api/webhooks/" + fakeToken + "\n"},
		{"webhook url", "webhook:\n  url: https://example.com/hook?key=" + fakeToken + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var n config.NotifyCfg
			err := yaml.Unmarshal([]byte(tc.yaml), &n)
			if err == nil {
				t.Fatal("inline secret in notify channel must be rejected at load, got nil error")
			}
			if strings.Contains(err.Error(), fakeToken) {
				t.Errorf("rejection error leaks the inline value: %q", err.Error())
			}
		})
	}
}

// TestNotifyChannels_EnvRefAccepted sanity-checks that well-formed env:
// references load for every notify channel after the tightening above.
func TestNotifyChannels_EnvRefAccepted(t *testing.T) {
	t.Parallel()
	input := `
telegram:
  bot_token: env:TELEGRAM_BOT_TOKEN
  chat_ids: ["1"]
slack:
  webhook_url: env:SLACK_WEBHOOK_URL
discord:
  webhook_url: env:DISCORD_WEBHOOK_URL
webhook:
  url: env:WEBHOOK_URL
  headers:
    Authorization: env:WEBHOOK_AUTH_HEADER
email:
  from: a@b
  to: [c@d]
  host: h
  port: 587
  password: env:SMTP_PASSWORD
`
	var n config.NotifyCfg
	if err := yaml.Unmarshal([]byte(input), &n); err != nil {
		t.Fatalf("env: references must load for all notify channels, got: %v", err)
	}
	if string(n.Telegram.BotToken) != "env:TELEGRAM_BOT_TOKEN" {
		t.Errorf("telegram bot_token = %q, want env:TELEGRAM_BOT_TOKEN", n.Telegram.BotToken)
	}
	if n.Webhook.Headers["Authorization"] != "env:WEBHOOK_AUTH_HEADER" {
		t.Errorf("webhook header = %q, want env:WEBHOOK_AUTH_HEADER", n.Webhook.Headers["Authorization"])
	}
}

// TestValidateEnvVarName covers the shared identifier check used by both the
// loader and the init wizard. Table-driven per AGENTS.md Go Conventions.
func TestValidateEnvVarName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"plain uppercase", "ANTHROPIC_API_KEY", false},
		{"lowercase", "my_var", false},
		{"leading underscore", "_PRIVATE", false},
		{"digits after alpha", "VAR123", false},
		{"empty", "", true},
		{"starts with digit", "1VAR", true},
		{"contains dash (anthropic key shape)", "sk-ant-abc", true},
		{"contains space", "MY VAR", true},
		{"contains equals", "VAR=1", true},
		{"known secret prefix sk-", "sk-abc123", true},
		{"known secret prefix ghp_", "ghp_abcdef123456", true},
		{"known secret prefix github_pat_", "github_pat_1234567890", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := config.ValidateEnvVarName(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateEnvVarName(%q) err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
			// If we rejected, make sure the raw input didn't leak into the message.
			// (Short inputs may share a 4-char prefix with the fingerprint — that's
			// acceptable because the fingerprint IS the first 4 chars; what we
			// forbid is the full input appearing verbatim when it's long enough
			// to matter.)
			if err != nil && len(tc.input) > 4 && strings.Contains(err.Error(), tc.input) {
				t.Errorf("error for %q leaks the raw input verbatim: %q", tc.input, err.Error())
			}
		})
	}
}

// TestRedactSecret_Fingerprint confirms the shape of the redaction helper so
// callers can rely on it (init wizard, loader, future call sites).
func TestRedactSecret_Fingerprint(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", "<empty>"},
		{"short", "abc", "..(3 chars)"},
		{"exactly 5", "abcde", "abcd..(5 chars)"},
		{"anthropic-shaped", fakePastedKey, "sk-a..(37 chars)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := config.RedactSecret(tc.input)
			if got != tc.want {
				t.Errorf("RedactSecret(%q) = %q, want %q", tc.input, got, tc.want)
			}
			// Fingerprints must never contain the tail of a long secret.
			if len(tc.input) > 8 && strings.Contains(got, tc.input[8:]) {
				t.Errorf("fingerprint %q contains tail of input", got)
			}
		})
	}
}
