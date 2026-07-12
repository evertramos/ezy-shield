package main

// Tests for `config notifier <name>` (issue #103, final config-group slice).
// Secret discipline mirrors configwizard_ai_test.go: pasted credentials
// (bot tokens, webhook URLs, SMTP passwords, auth header values) land only
// in .env (0600) — never in config.yaml or on stdout. Table-driven with
// scripted prompts per AGENTS.md Go Conventions.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// notifierTokenReader returns tokens in sequence, one per tokenRead call
// (the webhook wizard reads two secrets: URL, then auth header value).
func notifierTokenReader(tokens ...string) func(string) (string, error) {
	i := 0
	return func(string) (string, error) {
		if i >= len(tokens) {
			return "", nil
		}
		t := tokens[i]
		i++
		return t, nil
	}
}

// TestRunConfigComponent_NotifierHappyPath drives every registered channel
// end to end on a fresh installation: channel merged into notify:, refs in
// YAML, secrets only in .env (0600), .bak kept, nothing leaked to stdout.
func TestRunConfigComponent_NotifierHappyPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		answers []string // scripted `ask` answers, in prompt order
		tokens  []string // successive no-echo secret reads
		wantEnv []string // KEY=value lines that must be present in .env
		check   func(t *testing.T, n *config.NotifyCfg)
	}{
		{
			name:    "telegram",
			answers: []string{"123456789,987654321", "warn,critical", ""},
			tokens:  []string{"tg-bot-token-secret"},
			wantEnv: []string{"TELEGRAM_BOT_TOKEN=tg-bot-token-secret"},
			check: func(t *testing.T, n *config.NotifyCfg) {
				tg := n.Telegram
				if tg == nil || string(tg.BotToken) != "env:TELEGRAM_BOT_TOKEN" {
					t.Fatalf("telegram = %+v, want env-ref bot token", tg)
				}
				if len(tg.ChatIDs) != 2 || tg.ChatIDs[0] != "123456789" {
					t.Errorf("chat_ids = %v", tg.ChatIDs)
				}
				if len(tg.Severity) != 2 || tg.Severity[0] != "warn" || tg.Severity[1] != "critical" {
					t.Errorf("severity = %v", tg.Severity)
				}
			},
		},
		{
			name: "email",
			answers: []string{"alerts@example.com", "ops@example.com,sec@example.com",
				"smtp.example.com", "", "", "mailer", "", ""},
			tokens:  []string{"smtp-password-secret"},
			wantEnv: []string{"SMTP_PASSWORD=smtp-password-secret"},
			check: func(t *testing.T, n *config.NotifyCfg) {
				e := n.Email
				if e == nil || string(e.Password) != "env:SMTP_PASSWORD" {
					t.Fatalf("email = %+v, want env-ref password", e)
				}
				if e.From != "alerts@example.com" || len(e.To) != 2 ||
					e.Host != "smtp.example.com" || e.Port != 587 ||
					e.Username != "mailer" || e.TLS != "starttls" {
					t.Errorf("email fields = %+v", e)
				}
				if len(e.Severity) != 0 {
					t.Errorf("severity = %v, want all (empty)", e.Severity)
				}
			},
		},
		{
			name:    "slack",
			answers: []string{"#security", "critical", ""},
			tokens:  []string{"https://hooks.slack.example/T000/B000/slack-hook-secret"},
			wantEnv: []string{"SLACK_WEBHOOK_URL=https://hooks.slack.example/T000/B000/slack-hook-secret"},
			check: func(t *testing.T, n *config.NotifyCfg) {
				sl := n.Slack
				if sl == nil || string(sl.WebhookURL) != "env:SLACK_WEBHOOK_URL" {
					t.Fatalf("slack = %+v, want env-ref webhook url", sl)
				}
				if sl.Channel != "#security" || len(sl.Severity) != 1 {
					t.Errorf("slack fields = %+v", sl)
				}
			},
		},
		{
			name:    "discord",
			answers: []string{"", ""},
			tokens:  []string{"https://discord.example/api/webhooks/discord-hook-secret"},
			wantEnv: []string{"DISCORD_WEBHOOK_URL=https://discord.example/api/webhooks/discord-hook-secret"},
			check: func(t *testing.T, n *config.NotifyCfg) {
				di := n.Discord
				if di == nil || string(di.WebhookURL) != "env:DISCORD_WEBHOOK_URL" {
					t.Fatalf("discord = %+v, want env-ref webhook url", di)
				}
			},
		},
		{
			name:    "webhook",
			answers: []string{"", "", "Authorization", ""},
			tokens:  []string{"https://siem.example/ingest/webhook-url-secret", "Bearer wh-header-secret"},
			wantEnv: []string{
				"WEBHOOK_URL=https://siem.example/ingest/webhook-url-secret",
				"WEBHOOK_AUTH_HEADER=Bearer wh-header-secret",
			},
			check: func(t *testing.T, n *config.NotifyCfg) {
				wh := n.Webhook
				if wh == nil || string(wh.URL) != "env:WEBHOOK_URL" {
					t.Fatalf("webhook = %+v, want env-ref url", wh)
				}
				if wh.Headers["Authorization"] != "env:WEBHOOK_AUTH_HEADER" {
					t.Errorf("headers = %v, want env-ref auth header value", wh.Headers)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			cfgPath := writeFile(t, dir, "config.yaml", validConfig)
			prompt := &scriptedPrompter{strings: tc.answers}
			deps := cdnDeps{TokenReader: notifierTokenReader(tc.tokens...)}

			out := captureStep(t, func(p *wPrinter) {
				if code := runConfigComponent(context.Background(), p, prompt, deps,
					"notifier", tc.name, cfgPath); code != validateExitOK {
					t.Errorf("exit code = %d, want 0", code)
				}
			})

			cfg, err := config.LoadConfig(cfgPath)
			if err != nil {
				t.Fatalf("saved config does not load: %v", err)
			}
			if cfg.Notify == nil {
				t.Fatal("notify section missing after wizard")
			}
			tc.check(t, cfg.Notify)

			// Secrets: never in config.yaml, never on stdout, only in .env.
			raw, _ := os.ReadFile(cfgPath) //nolint:gosec // test path
			for _, tok := range tc.tokens {
				if strings.Contains(string(raw), tok) {
					t.Errorf("config.yaml contains a raw secret:\n%s", raw)
				}
				if strings.Contains(out, tok) {
					t.Errorf("stdout leaks a secret: %q", out)
				}
			}
			envPath := filepath.Join(dir, envFileName)
			envRaw, err := os.ReadFile(envPath) //nolint:gosec // test path
			if err != nil {
				t.Fatalf("expected .env: %v", err)
			}
			for _, want := range tc.wantEnv {
				if !strings.Contains(string(envRaw), want) {
					t.Errorf(".env missing %q:\n%s", want, envRaw)
				}
			}
			if st, _ := os.Stat(envPath); st.Mode().Perm() != 0o600 {
				t.Errorf(".env mode = %o, want 0600", st.Mode().Perm())
			}

			// Pre-existing config survives; .bak holds the original.
			if len(cfg.Collectors) != 1 || cfg.Collectors[0].Unit != "sshd" {
				t.Errorf("original collectors lost in merge: %+v", cfg.Collectors)
			}
			if bak, err := os.ReadFile(cfgPath + ".bak"); err != nil || string(bak) != validConfig { //nolint:gosec // test path
				t.Errorf(".bak missing or differs from original (err=%v)", err)
			}
			for _, want := range []string{"Changed keys:", "notify." + tc.name, "added channel", "config validate"} {
				if !strings.Contains(out, want) {
					t.Errorf("stdout missing %q:\n%s", want, out)
				}
			}
		})
	}
}

// notifyTelegramEntry is appended to validConfig when a test needs a
// pre-existing channel (with shared tuning that must survive edits).
const notifyTelegramEntry = `notify:
  rate_limit_per_minute: 10
  telegram:
    bot_token: env:TELEGRAM_BOT_TOKEN
    chat_ids: ["1"]
`

// TestRunConfigComponent_NotifierReplacesExisting reconfigures an existing
// channel: replaced in place, shared notify tuning preserved.
func TestRunConfigComponent_NotifierReplacesExisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml", validConfig+notifyTelegramEntry)
	prompt := &scriptedPrompter{strings: []string{"42", "", ""}}
	deps := cdnDeps{TokenReader: notifierTokenReader("tg-rotated")}

	out := captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, prompt, deps,
			"notifier", "telegram", cfgPath); code != validateExitOK {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("saved config does not load: %v", err)
	}
	if cfg.Notify.RateLimitPerMinute != 10 {
		t.Errorf("shared tuning lost on replace: %+v", cfg.Notify)
	}
	if len(cfg.Notify.Telegram.ChatIDs) != 1 || cfg.Notify.Telegram.ChatIDs[0] != "42" {
		t.Errorf("chat_ids = %v, want replaced value", cfg.Notify.Telegram.ChatIDs)
	}
	if !strings.Contains(out, "replaced channel") {
		t.Errorf("summary should say 'replaced channel':\n%s", out)
	}
}

// TestRunConfigComponent_NotifierRemove is the disable path: declining the
// configure prompt offers removal. Other channels and shared tuning stay.
func TestRunConfigComponent_NotifierRemove(t *testing.T) {
	t.Parallel()

	t.Run("channel removed", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig+notifyTelegramEntry)
		prompt := &scriptedPrompter{bools: []bool{false, true}} // decline configure, accept remove

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"notifier", "telegram", cfgPath); code != validateExitOK {
				t.Errorf("exit code = %d, want 0", code)
			}
		})

		cfg, err := config.LoadConfig(cfgPath)
		if err != nil {
			t.Fatalf("saved config does not load: %v", err)
		}
		if cfg.Notify == nil || cfg.Notify.Telegram != nil {
			t.Errorf("telegram should be removed, notify kept: %+v", cfg.Notify)
		}
		if cfg.Notify.RateLimitPerMinute != 10 {
			t.Errorf("shared tuning lost on remove: %+v", cfg.Notify)
		}
		if !strings.Contains(out, "notify.telegram — removed channel") {
			t.Errorf("summary should show the removal:\n%s", out)
		}
	})

	t.Run("removal declined leaves file untouched", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig+notifyTelegramEntry)
		prompt := &scriptedPrompter{bools: []bool{false, false}}

		captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"notifier", "telegram", cfgPath); code != validateExitError {
				t.Errorf("exit code = %d, want %d", code, validateExitError)
			}
		})
		assertUnchanged(t, cfgPath, validConfig+notifyTelegramEntry)
	})

	t.Run("nothing to remove", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig)
		prompt := &scriptedPrompter{bools: []bool{false}}

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"notifier", "slack", cfgPath); code != validateExitError {
				t.Errorf("exit code = %d, want %d", code, validateExitError)
			}
		})
		assertUnchanged(t, cfgPath, validConfig)
		if !strings.Contains(out, "no slack notifier is configured") {
			t.Errorf("stdout should explain there is nothing to remove:\n%s", out)
		}
	})
}

// TestRunConfigComponent_NotifierAborts covers operator-input abort paths:
// all must exit non-zero without touching config.yaml or .env.
func TestRunConfigComponent_NotifierAborts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		channel string
		answers []string
		wantOut string
	}{
		{"telegram no chat ids", "telegram", []string{}, "at least one chat ID is required"},
		{"telegram bad severity", "telegram", []string{"1", "urgent"}, `invalid severity "urgent"`},
		{"email missing host", "email", []string{"a@b.c", "d@e.f", ""}, "from, to, and SMTP host are all required"},
		{"email bad port", "email", []string{"a@b.c", "d@e.f", "smtp.h", "70000"}, "invalid SMTP port"},
		{"email bad tls", "email", []string{"a@b.c", "d@e.f", "smtp.h", "", "ssl3"}, `invalid TLS mode "ssl3"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			cfgPath := writeFile(t, dir, "config.yaml", validConfig)
			prompt := &scriptedPrompter{strings: tc.answers}

			out := captureStep(t, func(p *wPrinter) {
				if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
					"notifier", tc.channel, cfgPath); code != validateExitError {
					t.Errorf("exit code = %d, want %d", code, validateExitError)
				}
			})
			assertUnchanged(t, cfgPath, validConfig)
			if _, err := os.Stat(filepath.Join(dir, envFileName)); !os.IsNotExist(err) {
				t.Errorf(".env must not exist on abort (err=%v)", err)
			}
			if !strings.Contains(out, tc.wantOut) {
				t.Errorf("stdout missing %q:\n%s", tc.wantOut, out)
			}
		})
	}
}

// TestRunConfigComponent_NotifierExternalEnvVar: option 2 (secret already in
// an operator-managed env var) — config references it, .env untouched, the
// no-echo reader never called.
func TestRunConfigComponent_NotifierExternalEnvVar(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml", validConfig)
	prompt := &scriptedPrompter{strings: []string{
		"7",            // chat IDs
		"",             // severity → all
		"2",            // choice: external env var
		"MY_BOT_TOKEN", // its name
	}}
	deps := cdnDeps{TokenReader: func(string) (string, error) {
		t.Error("token reader must not be called for an external secret")
		return "", nil
	}}

	captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, prompt, deps,
			"notifier", "telegram", cfgPath); code != validateExitOK {
			t.Errorf("exit code = %d, want 0", code)
		}
	})

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("saved config does not load: %v", err)
	}
	if string(cfg.Notify.Telegram.BotToken) != "env:MY_BOT_TOKEN" {
		t.Errorf("bot_token = %q, want env:MY_BOT_TOKEN", cfg.Notify.Telegram.BotToken)
	}
	if _, err := os.Stat(filepath.Join(dir, envFileName)); !os.IsNotExist(err) {
		t.Errorf(".env must not be created for an externally managed secret (err=%v)", err)
	}
}

// TestRunConfigComponent_NotifierSkipPaste covers ENTER-to-skip at the
// secret prompt: an existing real value in .env is kept; otherwise the
// placeholder is written — either way the config change still lands.
func TestRunConfigComponent_NotifierSkipPaste(t *testing.T) {
	t.Parallel()
	skipDeps := cdnDeps{TokenReader: func(string) (string, error) { return "", nil }}

	t.Run("existing value kept", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig)
		writeFile(t, dir, envFileName, "TELEGRAM_BOT_TOKEN=tg-real\n")

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p,
				&scriptedPrompter{strings: []string{"7"}}, skipDeps,
				"notifier", "telegram", cfgPath); code != validateExitOK {
				t.Errorf("exit code = %d, want 0", code)
			}
		})
		envRaw, _ := os.ReadFile(filepath.Join(dir, envFileName)) //nolint:gosec // test path
		if !strings.Contains(string(envRaw), "TELEGRAM_BOT_TOKEN=tg-real") ||
			strings.Contains(string(envRaw), envAPIKeyPlaceholder) {
			t.Errorf("existing real value must be kept, not overwritten:\n%s", envRaw)
		}
		if !strings.Contains(out, "kept") {
			t.Errorf("stdout should say the existing value was kept:\n%s", out)
		}
	})

	t.Run("placeholder written", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig)

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p,
				&scriptedPrompter{strings: []string{"7"}}, skipDeps,
				"notifier", "telegram", cfgPath); code != validateExitOK {
				t.Errorf("exit code = %d, want 0", code)
			}
		})
		envRaw, err := os.ReadFile(filepath.Join(dir, envFileName)) //nolint:gosec // test path
		if err != nil {
			t.Fatalf("expected placeholder .env: %v", err)
		}
		if !strings.Contains(string(envRaw), "TELEGRAM_BOT_TOKEN="+envAPIKeyPlaceholder) {
			t.Errorf(".env missing placeholder line:\n%s", envRaw)
		}
		if !strings.Contains(out, "placeholder") {
			t.Errorf("stdout should point at the placeholder:\n%s", out)
		}
	})
}

// TestRunConfigComponent_NotifierUnknownName: a typo lists what IS registered.
func TestRunConfigComponent_NotifierUnknownName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml", validConfig)

	out := captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, &scriptedPrompter{}, cdnDeps{},
			"notifier", "pagerduty", cfgPath); code != validateExitError {
			t.Errorf("exit code = %d, want %d", code, validateExitError)
		}
	})
	for _, want := range []string{`unknown notifier "pagerduty"`,
		"discord", "email", "slack", "telegram", "webhook"} {
		if !strings.Contains(out, want) {
			t.Errorf("error should name the miss and list channels, missing %q:\n%s", want, out)
		}
	}
}

// TestResolveWebhookHeaders covers the daemon-side companion of the webhook
// wizard: env: references in header values resolve from the environment,
// plain values pass through, and failures never echo a secret — only the
// header NAME.
func TestResolveWebhookHeaders(t *testing.T) {
	const secret = "Bearer wh-resolved-secret"
	t.Setenv("EZY_TEST_WH_AUTH", secret)

	t.Run("env reference resolved, plain passthrough", func(t *testing.T) {
		got, err := resolveWebhookHeaders(map[string]string{
			"Authorization": "env:EZY_TEST_WH_AUTH",
			"X-Plain":       "not-a-secret",
		})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got["Authorization"] != secret || got["X-Plain"] != "not-a-secret" {
			t.Errorf("resolved = %v", got)
		}
	})

	t.Run("missing var errors with header name only", func(t *testing.T) {
		_, err := resolveWebhookHeaders(map[string]string{
			"X-Auth": "env:EZY_TEST_WH_DEFINITELY_UNSET",
		})
		if err == nil {
			t.Fatal("expected error for unset env var")
		}
		if !strings.Contains(err.Error(), "X-Auth") {
			t.Errorf("error should carry the header name: %v", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaks a resolved secret: %v", err)
		}
	})

	t.Run("malformed env reference redacted", func(t *testing.T) {
		const pasted = "env:sk-ant-fake-1234567890123456789012345"
		_, err := resolveWebhookHeaders(map[string]string{"Authorization": pasted})
		if err == nil {
			t.Fatal("expected error for malformed env: reference")
		}
		if strings.Contains(err.Error(), strings.TrimPrefix(pasted, "env:")) {
			t.Errorf("error leaks the pasted value verbatim: %v", err)
		}
	})

	t.Run("nil and empty maps pass through", func(t *testing.T) {
		if got, err := resolveWebhookHeaders(nil); err != nil || got != nil {
			t.Errorf("nil map: got %v, %v", got, err)
		}
	})
}

// TestNotifierSecret_StringRedacts locks the %+v discipline for the struct
// that briefly holds a pasted credential.
func TestNotifierSecret_StringRedacts(t *testing.T) {
	t.Parallel()
	s := notifierSecret{envVar: "X", token: "super-secret-value"}
	if got := s.String(); strings.Contains(got, "super-secret-value") {
		t.Errorf("String() leaks the token: %q", got)
	}
	if !strings.Contains(s.String(), "<redacted>") {
		t.Errorf("String() should mark the token redacted: %q", s.String())
	}
}
