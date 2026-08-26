// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the init Notifications step (issue #290): interactive channel
// selection reusing the `config notifier` flows, the non-interactive answers
// schema, literal-secret rejection, and the generated notify: block.

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// TestInitNotify_InteractiveTelegramExternalEnv drives runNotifyStep through
// the shared telegram flow: channels enabled, telegram selected, chat IDs
// given, secret option 2 (externally managed env var, default name kept),
// every other channel declined.
func TestInitNotify_InteractiveTelegramExternalEnv(t *testing.T) {
	installTokenReader(t, func(string) (string, error) {
		t.Fatal("tokenReader must not run for the external-env path")
		return "", nil
	})
	input := strings.Join([]string{
		"y",      // configure channels now?
		"y",      // add telegram?
		"123456", // chat IDs
		"",       // severity filter (all)
		"2",      // secret: option 2 (external env var)
		"",       // env var name (keep default TELEGRAM_BOT_TOKEN)
		"n",      // email
		"n",      // slack
		"n",      // discord
		"n",      // webhook
	}, "\n") + "\n"

	state := &wizardState{}
	sc := bufio.NewScanner(strings.NewReader(input))
	ask, askBool := newAskFuncs(sc, os.Stdout, false)
	runNotifyStep(&wPrinter{w: os.Stdout}, closurePrompter{askFn: ask, askBoolFn: askBool},
		cdnDeps{}, state, t.TempDir(), false)

	if state.notify == nil || state.notify.Telegram == nil {
		t.Fatalf("telegram channel not configured: %+v", state.notify)
	}
	tg := state.notify.Telegram
	if string(tg.BotToken) != "env:TELEGRAM_BOT_TOKEN" {
		t.Errorf("bot_token = %q, want env:TELEGRAM_BOT_TOKEN", tg.BotToken)
	}
	if len(tg.ChatIDs) != 1 || tg.ChatIDs[0] != "123456" {
		t.Errorf("chat_ids = %v", tg.ChatIDs)
	}
	if state.notify.Email != nil || state.notify.Slack != nil {
		t.Errorf("declined channels must stay nil: %+v", state.notify)
	}
	if state.notifyPostSave != nil {
		t.Error("external env var must not produce a .env post-save hook")
	}

	// The generated config must serialize and validate with the section.
	state.armed = false
	data, err := renderGeneratedConfig(state)
	if err != nil {
		t.Fatalf("renderGeneratedConfig: %v", err)
	}
	if !strings.Contains(string(data), "notify:") || !strings.Contains(string(data), "env:TELEGRAM_BOT_TOKEN") {
		t.Fatalf("generated config lacks the notify block:\n%s", data)
	}
}

// TestInitNotify_YesModeSkips: unattended --yes runs must not invent
// channels (they need operator-specific values).
func TestInitNotify_YesModeSkips(t *testing.T) {
	state := &wizardState{}
	runNotifyStep(&wPrinter{w: os.Stdout}, closurePrompter{}, cdnDeps{}, state, t.TempDir(), true)
	if state.notify != nil {
		t.Fatalf("--yes run configured channels: %+v", state.notify)
	}
}

// TestNonInteractive_NotifyMultiChannel drives a multi-channel answers file
// through the full non-interactive init and asserts the generated notify:
// block, defaults, env-only secrets, and .env placeholders.
func TestNonInteractive_NotifyMultiChannel(t *testing.T) {
	stubDetection(t)
	etc := filepath.Join(t.TempDir(), "etc")

	answers := writeAnswers(t, `
allowlist:
  admin_ips: [203.0.113.4]
notify:
  telegram:
    chat_ids: ["-100123", "456"]
    severity: [critical]
  email:
    from: ezyshield@example.com
    to: [admin@example.com, ops@example.com]
    host: smtp.example.com
    username: ezyshield@example.com
    password_env: MY_SMTP_PASS
  webhook:
    url_env: OPS_WEBHOOK_URL
    auth_header_name: Authorization
`)

	_, _, err := runInit(t, "--answers", answers, "--config-dir", etc)
	if err != nil {
		t.Fatalf("non-interactive init failed: %v", err)
	}

	cfg, err := config.LoadConfig(filepath.Join(etc, "config.yaml"))
	if err != nil {
		t.Fatalf("generated config.yaml did not validate: %v", err)
	}
	n := cfg.Notify
	if n == nil || n.Telegram == nil || n.Email == nil || n.Webhook == nil {
		t.Fatalf("notify block incomplete: %+v", n)
	}
	if string(n.Telegram.BotToken) != "env:TELEGRAM_BOT_TOKEN" {
		t.Errorf("telegram token = %q, want the default env ref", n.Telegram.BotToken)
	}
	if len(n.Telegram.ChatIDs) != 2 || n.Telegram.Severity[0] != "critical" {
		t.Errorf("telegram = %+v", n.Telegram)
	}
	if n.Email.Port != 587 || n.Email.TLS != "starttls" {
		t.Errorf("email defaults not applied: port=%d tls=%q", n.Email.Port, n.Email.TLS)
	}
	if string(n.Email.Password) != "env:MY_SMTP_PASS" {
		t.Errorf("email password = %q, want env:MY_SMTP_PASS", n.Email.Password)
	}
	if string(n.Webhook.URL) != "env:OPS_WEBHOOK_URL" {
		t.Errorf("webhook url = %q", n.Webhook.URL)
	}
	if got := n.Webhook.Headers["Authorization"]; got != "env:WEBHOOK_AUTH_HEADER" {
		t.Errorf("webhook auth header = %q, want default env ref", got)
	}
	if n.Slack != nil || n.Discord != nil {
		t.Errorf("unrequested channels present: %+v", n)
	}

	// Placeholders stubbed for every referenced secret.
	env, _ := os.ReadFile(filepath.Join(etc, ".env")) //nolint:gosec // test path under t.TempDir
	for _, name := range []string{"TELEGRAM_BOT_TOKEN", "MY_SMTP_PASS", "OPS_WEBHOOK_URL", "WEBHOOK_AUTH_HEADER"} {
		if !strings.Contains(string(env), name+"=") {
			t.Errorf(".env missing stub for %s; body=%q", name, string(env))
		}
	}
}

// TestNonInteractive_NotifySecretRejected: a literal token in the answers
// file fails closed before any write, with the pointed env-field message.
func TestNonInteractive_NotifySecretRejected(t *testing.T) {
	stubDetection(t)
	etc := filepath.Join(t.TempDir(), "etc")

	answers := writeAnswers(t, `
notify:
  telegram:
    chat_ids: ["123"]
    bot_token: "8123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
`)
	_, _, err := runInit(t, "--answers", answers, "--config-dir", etc)
	if err == nil || !strings.Contains(err.Error(), "bot_token_env") {
		t.Fatalf("err = %v, want literal-secret rejection naming bot_token_env", err)
	}
	if strings.Contains(err.Error(), "AAAAAAAA") {
		t.Fatalf("error echoes the secret: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(etc, "config.yaml")); !os.IsNotExist(statErr) {
		t.Fatal("rejection must happen before any write")
	}
}

// TestNonInteractive_NotifyValidation: answer-level requiredness problems are
// all listed at once.
func TestNonInteractive_NotifyValidation(t *testing.T) {
	stubDetection(t)
	etc := filepath.Join(t.TempDir(), "etc")

	answers := writeAnswers(t, `
notify:
  telegram:
    severity: [urgent]
  email:
    from: a@example.com
`)
	_, _, err := runInit(t, "--answers", answers, "--config-dir", etc)
	if err == nil {
		t.Fatal("invalid notify answers must fail")
	}
	for _, want := range []string{"chat_ids", "invalid severity", "'to' is required", "'host' is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %v lacks %q", err, want)
		}
	}
}
