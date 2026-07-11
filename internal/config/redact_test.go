// Package config — redaction gate tests for the `config show` display path
// (SECURITY-REVIEW §4: secrets never in any observable channel).
package config_test

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/evertramos/ezy-shield/internal/config"
)

// TestConfigRedacted_WebhookHeaderValues verifies that webhook header values
// — the only config fields that can legally carry a raw credential — are
// replaced with the redaction marker, keys preserved, original untouched.
func TestConfigRedacted_WebhookHeaderValues(t *testing.T) {
	t.Parallel()
	const headerSecret = "Bearer wh-" + fakeToken
	cfg := &config.Config{
		DataDir: "/var/lib/ezyshield",
		Notify: &config.NotifyCfg{
			Webhook: &config.WebhookCfg{
				URL: config.SecretRef("env:EZY_TEST_WH_URL"),
				Headers: map[string]string{
					"Authorization": headerSecret,
					"X-API-Key":     fakeToken,
				},
			},
		},
	}

	red := cfg.Redacted()

	for k, v := range red.Notify.Webhook.Headers {
		if v != config.RedactedMarker {
			t.Errorf("redacted header %q = %q, want %q", k, v, config.RedactedMarker)
		}
	}
	if len(red.Notify.Webhook.Headers) != 2 {
		t.Errorf("redacted header count = %d, want 2 (keys must be preserved)",
			len(red.Notify.Webhook.Headers))
	}

	// The original must not be mutated — the daemon still needs real values.
	if cfg.Notify.Webhook.Headers["Authorization"] != headerSecret {
		t.Error("Redacted() mutated the original config's header values")
	}

	// The actual leak gate: a full YAML dump of the redacted view must not
	// contain either raw header value, while env: references stay visible.
	dump, err := yaml.Marshal(red)
	if err != nil {
		t.Fatalf("yaml.Marshal(redacted): %v", err)
	}
	if strings.Contains(string(dump), fakeToken) {
		t.Errorf("redacted YAML dump leaks header value: %s", dump)
	}
	if !strings.Contains(string(dump), "env:EZY_TEST_WH_URL") {
		t.Errorf("redacted YAML dump lost the env: reference: %s", dump)
	}
}

// TestConfigRedacted_NilSafety exercises the nil/empty paths: no panic and
// no unnecessary copies.
func TestConfigRedacted_NilSafety(t *testing.T) {
	t.Parallel()
	var nilCfg *config.Config
	if got := nilCfg.Redacted(); got != nil {
		t.Errorf("nil.Redacted() = %v, want nil", got)
	}

	for name, cfg := range map[string]*config.Config{
		"no notify":         {DataDir: "/d"},
		"notify no webhook": {DataDir: "/d", Notify: &config.NotifyCfg{}},
		"webhook no headers": {DataDir: "/d", Notify: &config.NotifyCfg{
			Webhook: &config.WebhookCfg{URL: config.SecretRef("env:X_URL")},
		}},
	} {
		red := cfg.Redacted()
		if red == nil {
			t.Errorf("%s: Redacted() = nil, want copy", name)
		}
	}
}
