package config

// Tests for the misplaced-credential guard (issue #172): credentials pasted
// into NON-secret fields must fail the load with an error that names the
// field but never carries the value, and legitimate values must never trip
// the heuristics (a false positive blocks the daemon from starting).

import (
	"strings"
	"testing"
)

const fakeAnthropicKey = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE-FAKEFAKEAA"

func TestLooksLikeCredential(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value string
		want  bool
	}{
		// Real-world key shapes → must match.
		{fakeAnthropicKey, true},
		{"sk-proj-AbCdEfGhIjKlMnOpQrStUvWx0123456789", true},
		{"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", true},
		{"github_pat_11ABCDEFG0123456789_abcdefghijk", true},
		{"glpat-AbCdEfGhIjKlMnOpQrSt", true},
		// Built by concatenation so GitHub's own push protection does not
		// flag this test fixture as a live Slack token.
		{"xoxb-" + "1234567890" + "-abcdefghijklmnop", true},
		{"AKIAIOSFODNN7EXAMPLE", true},
		{"AIzaSyA0123456789AbCdEfGhIjKlMnOpQrStU", true},
		// Generic high-entropy token (mixed case + digits, len >= 32).
		{"q8Fz2LxWv9Kt4Jm7Rp0Ys3Nb6Hd1Gc5A", true},
		// Legit values → must NOT match.
		{"anthropic", false},
		{"claude-3-5-haiku-latest", false},
		{"llama3", false},
		{"http://localhost:11434", false},
		{"https://api.example.com/v1", false},
		{"/var/lib/ezyshield/GeoLite2-Country.mmdb", false},
		{"/var/log/nginx/access.log", false},
		{"ssh", false},
		{"wordpress-nginx", false},
		{"smtp.example.com", false},
		{"alerts@example.com", false},
		{"#security", false},
		{"-1001234567890", false},                   // telegram chat ID
		{"0123456789abcdef0123456789abcdef", false}, // CF account ID: lower hex, no case mix
		{strings.Repeat("a1b2c3d4", 8), false},      // 64-char lower hex (docker ID)
		{"env:ANTHROPIC_API_KEY", false},            // sanctioned reference shape
		{"env:" + fakeAnthropicKey, false},          // env:-prefixed handled by SecretRef path
		{"ezyshield_blocked", false},
		{"sk-tiny", false}, // known prefix but too short to be a key
		{"", false},
	}
	for _, tc := range cases {
		if got := looksLikeCredential(tc.value); got != tc.want {
			t.Errorf("looksLikeCredential(%.12q...) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

// TestScan_KeyInWrongField pastes a key into every plausible wrong field and
// demands: load fails, the error names the field, and the key value never
// appears in the error text.
func TestScan_KeyInWrongField(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		yaml      string
		wantField string
	}{
		{
			name:      "ai.provider single form",
			yaml:      "ai:\n  provider: " + fakeAnthropicKey + "\n",
			wantField: "ai.provider",
		},
		{
			name:      "ai.model",
			yaml:      "ai:\n  provider: anthropic\n  model: " + fakeAnthropicKey + "\n",
			wantField: "ai.model",
		},
		{
			name:      "ai.endpoint",
			yaml:      "ai:\n  provider: ollama\n  endpoint: " + fakeAnthropicKey + "\n",
			wantField: "ai.endpoint",
		},
		{
			name: "ai.providers[].name",
			yaml: "ai:\n  providers:\n    - name: " + fakeAnthropicKey + "\n      priority: 1\n",
			// The scan walks the whole tree before validateAI runs.
			wantField: "ai.providers[0].name",
		},
		{
			name:      "notify.email.username",
			yaml:      "notify:\n  email:\n    host: smtp.example.com\n    port: 587\n    from: a@b.c\n    to: [a@b.c]\n    username: " + fakeAnthropicKey + "\n",
			wantField: "notify.email.username",
		},
		{
			name:      "enrich.db_path",
			yaml:      "enrich:\n  db_path: " + fakeAnthropicKey + "\n",
			wantField: "enrich.db_path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadConfigReader(strings.NewReader(tc.yaml), "config.yaml")
			if err == nil {
				t.Fatal("config with a pasted credential loaded without error")
			}
			msg := err.Error()
			if strings.Contains(msg, fakeAnthropicKey) {
				t.Fatalf("error echoes the credential: %s", msg)
			}
			// The 4-char fingerprint (redactSecret) is the allowed maximum.
			if strings.Contains(msg, fakeAnthropicKey[:8]) {
				t.Errorf("error leaks more than the 4-char fingerprint: %s", msg)
			}
			if !strings.Contains(msg, tc.wantField) {
				t.Errorf("error does not name field %s: %s", tc.wantField, msg)
			}
		})
	}
}

// TestScan_LegitConfigLoads is the false-positive gate: a fully featured,
// realistic config must pass the scan untouched.
func TestScan_LegitConfigLoads(t *testing.T) {
	t.Parallel()
	yaml := `
data_dir: /var/lib/ezyshield
collectors:
  - kind: journald
    unit: ssh
  - kind: file
    path: /var/log/nginx/access.log
  - kind: docker
    container: wordpress-nginx
    parser: nginx
enforce:
  nftables:
    table: ezyshield
    set: banned
  cloudflare:
    api_token: env:CF_API_TOKEN
    account_id: "0123456789abcdef0123456789abcdef"
    list_name: ezyshield_blocked
ai:
  provider: anthropic
  model: claude-3-5-haiku-latest
  api_key: env:ANTHROPIC_API_KEY
notify:
  telegram:
    bot_token: env:TG_TOKEN
    chat_ids: ["-1001234567890"]
  email:
    host: smtp.example.com
    port: 587
    from: alerts@example.com
    to: [ops@example.com]
    username: mailer
    password: env:SMTP_PASSWORD
enrich:
  db_path: /var/lib/ezyshield/GeoLite2-Country.mmdb
  asn_path: /var/lib/ezyshield/GeoLite2-ASN.mmdb
  auto_update: true
  license_key: env:MAXMIND_LICENSE_KEY
`
	if _, err := LoadConfigReader(strings.NewReader(yaml), "config.yaml"); err != nil {
		t.Fatalf("legit config tripped the secret guard: %v", err)
	}
}

// TestScan_WebhookHeadersExempt: raw header values are legal by design (and
// redacted in `config show`); the scan must not reject them.
func TestScan_WebhookHeadersExempt(t *testing.T) {
	t.Parallel()
	yaml := "notify:\n  webhook:\n    url: env:WEBHOOK_URL\n    headers:\n      Authorization: Bearer q8Fz2LxWv9Kt4Jm7Rp0Ys3Nb6Hd1Gc5A\n"
	if _, err := LoadConfigReader(strings.NewReader(yaml), "config.yaml"); err != nil {
		t.Fatalf("webhook header value tripped the secret guard: %v", err)
	}
}

// TestValidateAI_SingleProvider covers the previously missing validation and
// the no-echo error contract for enum-ish fields.
func TestValidateAI_SingleProvider(t *testing.T) {
	t.Parallel()

	t.Run("typo echoes the short value", func(t *testing.T) {
		t.Parallel()
		_, err := LoadConfigReader(strings.NewReader("ai:\n  provider: anthropicc\n"), "config.yaml")
		if err == nil || !strings.Contains(err.Error(), `"anthropicc"`) {
			t.Fatalf("want unknown-provider error echoing the typo, got: %v", err)
		}
	})

	t.Run("long value is fingerprinted not echoed", func(t *testing.T) {
		t.Parallel()
		// 45 lowercase chars: passes the credential scan (no case mix) but
		// must still not be echoed by the enum error (> 40 chars).
		long := strings.Repeat("abcde", 9)
		_, err := LoadConfigReader(strings.NewReader("ai:\n  provider: "+long+"\n"), "config.yaml")
		if err == nil {
			t.Fatal("unknown provider loaded without error")
		}
		if strings.Contains(err.Error(), long) {
			t.Fatalf("error echoes the long value: %v", err)
		}
	})
}
