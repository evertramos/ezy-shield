package main

// Post-install notifier wizards for `config notifier <name>` (issue #103,
// final config-group slice). The init wizard has no notifier sub-flow, so
// unlike the enforcer/ai/collector wizards there is nothing to extract —
// these flows are new, but they are built strictly on the same primitives:
// the shared prompt closures (newAskFuncs), the registry + atomic write path
// (runConfigComponent), and the existing Config schema (internal/config).
//
// Secret discipline mirrors the AI wizard: credential values (bot tokens,
// webhook URLs, SMTP passwords, auth header values) are read echo-suppressed
// and land ONLY in the .env file next to config.yaml; config.yaml carries
// "env:VARNAME" references. Nothing here may print, log, or error with a
// token value (SECURITY-REVIEW §4).

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/evertramos/ezy-shield/internal/config"
)

// notifierSecretEnvVar fixes the default env var per channel secret, same
// single-source-of-truth idea as aiProviderKeyName (issue #13 §1): the
// operator is never asked to invent a NAME unless they manage the var
// themselves (option 2).
var notifierSecretEnvVar = map[string]string{
	"telegram": "TELEGRAM_BOT_TOKEN",
	"email":    "SMTP_PASSWORD",
	"slack":    "SLACK_WEBHOOK_URL",
	"discord":  "DISCORD_WEBHOOK_URL",
	"webhook":  "WEBHOOK_URL",
}

// webhookAuthHeaderEnvVar holds the optional second webhook secret: the
// value of the auth header (e.g. a bearer token) sent on every request.
const webhookAuthHeaderEnvVar = "WEBHOOK_AUTH_HEADER"

// notifierSecret is the outcome of the two-option secret prompt shared by
// every notifier channel. token is held only between the prompt and the
// .env write — same discipline as aiStep.token, never printed or logged.
type notifierSecret struct {
	envVar   string
	token    string
	external bool
}

// String masks the token so a %+v in tests or debug logging can never leak it.
func (s notifierSecret) String() string {
	tokMark := "<empty>"
	if s.token != "" {
		tokMark = "<redacted>"
	}
	return fmt.Sprintf("notifierSecret{envVar=%q external=%v token=%s}",
		s.envVar, s.external, tokMark)
}

// askNotifierSecret presents the same two-option prompt the AI wizard uses
// (issue #22): paste the value echo-suppressed (option 1, default) or point
// at an env var the operator already manages (option 2, .env untouched).
// ENTER at the paste prompt is valid — the placeholder path handles .env.
func askNotifierSecret(p *wPrinter, pr prompter, tokenRead func(prompt string) (string, error),
	what, defEnvVar string) notifierSecret {
	if tokenRead == nil {
		tokenRead = tokenReader
	}
	sec := notifierSecret{envVar: defEnvVar}
	p.printf("\n  How do you want to provide the %s?\n", what)
	p.println("    1) Paste it here — stored in the .env file next to config.yaml (recommended)")
	p.println("    2) I already have it in an env var (e.g. from sops / vault / LoadCredential)")
	if strings.TrimSpace(pr.ask("Choice", "1")) == "2" {
		sec.external = true
		for attempt := 0; attempt < 3; attempt++ {
			name := pr.ask(fmt.Sprintf("Env var name holding the %s", what), defEnvVar)
			if err := config.ValidateEnvVarName(name); err != nil {
				p.printf("    invalid env var name: %v\n", err)
				continue
			}
			sec.envVar = name
			return sec
		}
		p.println("    Too many invalid attempts; keeping the default env var name.")
		return sec
	}
	tok, err := tokenRead(fmt.Sprintf("  Paste the %s (input hidden, ENTER to skip): ", what))
	if err != nil {
		// No controlling tty (non-interactive run): fall through to the
		// placeholder path, exactly like the AI key prompt.
		return sec
	}
	sec.token = tok
	return sec
}

// envPostSave returns the hook that merges this secret into .env after
// config.yaml is committed, or nil when the operator manages the var
// externally. Reuses the generic upsert in writeAIEnvFile: rotation,
// keep-existing, and placeholder semantics are identical to the AI wizard.
func (s notifierSecret) envPostSave(p *wPrinter, configDir string) func() error {
	if s.external {
		return nil
	}
	return func() error {
		wrote, kept, err := writeAIEnvFile(configDir, s.envVar, s.token)
		if err != nil {
			return err
		}
		envPath := configDir + "/" + envFileName
		switch {
		case kept:
			p.printf("  kept %s (existing %s preserved)\n", envPath, s.envVar)
		case wrote && s.token == "":
			p.printf("  wrote %s (chmod 600, placeholder — set %s there, then restart the daemon)\n",
				envPath, s.envVar)
		case wrote:
			p.printf("  wrote %s (chmod 600, %s merged)\n", envPath, s.envVar)
		}
		return nil
	}
}

// chainPostSave runs the non-nil hooks in order (webhook has two secrets).
func chainPostSave(hooks ...func() error) func() error {
	var live []func() error
	for _, h := range hooks {
		if h != nil {
			live = append(live, h)
		}
	}
	if len(live) == 0 {
		return nil
	}
	return func() error {
		for _, h := range live {
			if err := h(); err != nil {
				return err
			}
		}
		return nil
	}
}

// notifierValidSeverities mirrors internal/config's validation set so the
// wizard rejects a typo at the prompt instead of at the re-validation step.
var notifierValidSeverities = map[string]bool{
	"info": true, "warn": true, "critical": true,
}

// askSeverityFilter prompts for the per-channel severity filter. Empty means
// all severities (the schema's zero value); anything else must be a comma
// list of info|warn|critical.
func askSeverityFilter(pr prompter) ([]string, error) {
	raw := strings.TrimSpace(pr.ask("Severity filter (comma-separated: info,warn,critical; empty = all)", ""))
	if raw == "" {
		return nil, nil
	}
	var out []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !notifierValidSeverities[s] {
			return nil, fmt.Errorf("invalid severity %q (must be info, warn, or critical)", s)
		}
		out = append(out, s)
	}
	return out, nil
}

// describeSeverity renders the filter for the changed-keys summary.
func describeSeverity(sev []string) string {
	if len(sev) == 0 {
		return "all"
	}
	return strings.Join(sev, ",")
}

// splitCommaList splits a comma-separated answer, trimming blanks.
func splitCommaList(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ensureNotify materialises the notify: section before a channel merge.
func ensureNotify(cfg *config.Config) *config.NotifyCfg {
	if cfg.Notify == nil {
		cfg.Notify = &config.NotifyCfg{}
	}
	return cfg.Notify
}

// notifierChannelSet reports whether name is currently configured.
func notifierChannelSet(n *config.NotifyCfg, name string) bool {
	if n == nil {
		return false
	}
	switch name {
	case "telegram":
		return n.Telegram != nil
	case "email":
		return n.Email != nil
	case "slack":
		return n.Slack != nil
	case "discord":
		return n.Discord != nil
	case "webhook":
		return n.Webhook != nil
	}
	return false
}

// clearNotifierChannel drops the channel from the notify: section. Shared
// tuning (rate_limit_per_minute, dedup_window_sec) and other channels are
// left untouched.
func clearNotifierChannel(n *config.NotifyCfg, name string) {
	switch name {
	case "telegram":
		n.Telegram = nil
	case "email":
		n.Email = nil
	case "slack":
		n.Slack = nil
	case "discord":
		n.Discord = nil
	case "webhook":
		n.Webhook = nil
	}
}

// removeNotifierIfConfirmed is the disable path, mirroring the collector
// wizard: the operator declined to configure name, so offer to remove an
// existing entry (default no). nil changed + nil err = nothing is written.
func removeNotifierIfConfirmed(p *wPrinter, pr prompter, cfg *config.Config,
	name string) ([]string, func() error, error) {
	if !notifierChannelSet(cfg.Notify, name) {
		p.printf("  no %s notifier is configured — nothing to do.\n", name)
		return nil, nil, nil
	}
	if !pr.askBool(fmt.Sprintf("Remove the existing %s notifier from config.yaml?", name), false) {
		return nil, nil, nil
	}
	clearNotifierChannel(cfg.Notify, name)
	return []string{fmt.Sprintf("notify.%s — removed channel", name)}, nil, nil
}

// channelVerb returns the changed-keys verb for a channel merge.
func channelVerb(replaced bool) string {
	if replaced {
		return "replaced"
	}
	return "added"
}

// wizardNotifierTelegram configures notify.telegram: chat IDs, severity
// filter, and the bot token (secret → .env).
func wizardNotifierTelegram(_ context.Context, p *wPrinter, pr prompter, deps cdnDeps,
	cfg *config.Config, configDir string) ([]string, func() error, error) {
	if !pr.askBool("Configure the telegram notification channel?", true) {
		return removeNotifierIfConfirmed(p, pr, cfg, "telegram")
	}
	chatIDs := splitCommaList(pr.ask("Telegram chat IDs (comma-separated)", ""))
	if len(chatIDs) == 0 {
		p.println("  at least one chat ID is required — aborting, nothing will be written.")
		return nil, nil, nil
	}
	sev, err := askSeverityFilter(pr)
	if err != nil {
		return nil, nil, err
	}
	sec := askNotifierSecret(p, pr, deps.TokenReader, "Telegram bot token", notifierSecretEnvVar["telegram"])

	n := ensureNotify(cfg)
	verb := channelVerb(n.Telegram != nil)
	n.Telegram = &config.TelegramCfg{
		BotToken: config.SecretRef("env:" + sec.envVar),
		ChatIDs:  chatIDs,
		Severity: sev,
	}
	changed := []string{fmt.Sprintf(
		"notify.telegram — %s channel (chat_ids=%s, severity=%s, bot_token=env:%s)",
		verb, strings.Join(chatIDs, ","), describeSeverity(sev), sec.envVar)}
	return changed, sec.envPostSave(p, configDir), nil
}

// wizardNotifierEmail configures notify.email. The SMTP password is prompted
// only when a username is given (anonymous relays need none) and follows the
// same secret path as every other channel.
func wizardNotifierEmail(_ context.Context, p *wPrinter, pr prompter, deps cdnDeps,
	cfg *config.Config, configDir string) ([]string, func() error, error) {
	if !pr.askBool("Configure the email notification channel?", true) {
		return removeNotifierIfConfirmed(p, pr, cfg, "email")
	}
	from := strings.TrimSpace(pr.ask("From address", ""))
	toList := splitCommaList(pr.ask("To addresses (comma-separated)", ""))
	host := strings.TrimSpace(pr.ask("SMTP host", ""))
	if from == "" || len(toList) == 0 || host == "" {
		p.println("  from, to, and SMTP host are all required — aborting, nothing will be written.")
		return nil, nil, nil
	}
	port, err := strconv.Atoi(strings.TrimSpace(pr.ask("SMTP port", "587")))
	if err != nil || port <= 0 || port > 65535 {
		return nil, nil, fmt.Errorf("invalid SMTP port (must be 1..65535)")
	}
	tlsMode := strings.ToLower(strings.TrimSpace(pr.ask("TLS mode (starttls/tls/none)", "starttls")))
	if tlsMode != "starttls" && tlsMode != "tls" && tlsMode != "none" {
		return nil, nil, fmt.Errorf("invalid TLS mode %q (must be starttls, tls, or none)", tlsMode)
	}
	username := strings.TrimSpace(pr.ask("SMTP username (empty = no auth)", ""))
	sev, err := askSeverityFilter(pr)
	if err != nil {
		return nil, nil, err
	}

	entry := &config.EmailCfg{
		From: from, To: toList, Host: host, Port: port,
		Username: username, TLS: tlsMode, Severity: sev,
	}
	var postSave func() error
	if username != "" {
		sec := askNotifierSecret(p, pr, deps.TokenReader, "SMTP password", notifierSecretEnvVar["email"])
		entry.Password = config.SecretRef("env:" + sec.envVar)
		postSave = sec.envPostSave(p, configDir)
	}

	n := ensureNotify(cfg)
	verb := channelVerb(n.Email != nil)
	n.Email = entry
	line := fmt.Sprintf("notify.email — %s channel (host=%s:%d, from=%s, to=%s, tls=%s, severity=%s",
		verb, host, port, from, strings.Join(toList, ","), tlsMode, describeSeverity(sev))
	if username != "" {
		line += ", password=env:" + strings.TrimPrefix(string(entry.Password), "env:")
	}
	line += ")"
	return []string{line}, postSave, nil
}

// wizardNotifierSlack configures notify.slack: optional channel override,
// severity filter, and the incoming-webhook URL (a capability URL — treated
// as a secret end to end).
func wizardNotifierSlack(_ context.Context, p *wPrinter, pr prompter, deps cdnDeps,
	cfg *config.Config, configDir string) ([]string, func() error, error) {
	if !pr.askBool("Configure the slack notification channel?", true) {
		return removeNotifierIfConfirmed(p, pr, cfg, "slack")
	}
	channel := strings.TrimSpace(pr.ask("Slack channel override (e.g. #security; empty = app default)", ""))
	sev, err := askSeverityFilter(pr)
	if err != nil {
		return nil, nil, err
	}
	sec := askNotifierSecret(p, pr, deps.TokenReader, "Slack webhook URL", notifierSecretEnvVar["slack"])

	n := ensureNotify(cfg)
	verb := channelVerb(n.Slack != nil)
	n.Slack = &config.SlackCfg{
		WebhookURL: config.SecretRef("env:" + sec.envVar),
		Channel:    channel,
		Severity:   sev,
	}
	changed := []string{fmt.Sprintf("notify.slack — %s channel (severity=%s, webhook_url=env:%s)",
		verb, describeSeverity(sev), sec.envVar)}
	return changed, sec.envPostSave(p, configDir), nil
}

// wizardNotifierDiscord configures notify.discord: severity filter and the
// webhook URL secret.
func wizardNotifierDiscord(_ context.Context, p *wPrinter, pr prompter, deps cdnDeps,
	cfg *config.Config, configDir string) ([]string, func() error, error) {
	if !pr.askBool("Configure the discord notification channel?", true) {
		return removeNotifierIfConfirmed(p, pr, cfg, "discord")
	}
	sev, err := askSeverityFilter(pr)
	if err != nil {
		return nil, nil, err
	}
	sec := askNotifierSecret(p, pr, deps.TokenReader, "Discord webhook URL", notifierSecretEnvVar["discord"])

	n := ensureNotify(cfg)
	verb := channelVerb(n.Discord != nil)
	n.Discord = &config.DiscordCfg{
		WebhookURL: config.SecretRef("env:" + sec.envVar),
		Severity:   sev,
	}
	changed := []string{fmt.Sprintf("notify.discord — %s channel (severity=%s, webhook_url=env:%s)",
		verb, describeSeverity(sev), sec.envVar)}
	return changed, sec.envPostSave(p, configDir), nil
}

// wizardNotifierWebhook configures notify.webhook: the endpoint URL secret
// plus an optional auth header. The header VALUE is a secret too — the YAML
// gets "env:WEBHOOK_AUTH_HEADER" and the daemon resolves it at startup
// (resolveWebhookHeaders in run.go); the raw value goes only to .env.
func wizardNotifierWebhook(_ context.Context, p *wPrinter, pr prompter, deps cdnDeps,
	cfg *config.Config, configDir string) ([]string, func() error, error) {
	if !pr.askBool("Configure the generic webhook notification channel?", true) {
		return removeNotifierIfConfirmed(p, pr, cfg, "webhook")
	}
	sev, err := askSeverityFilter(pr)
	if err != nil {
		return nil, nil, err
	}
	urlSec := askNotifierSecret(p, pr, deps.TokenReader, "webhook endpoint URL", notifierSecretEnvVar["webhook"])

	var headers map[string]string
	headerHooks := []func() error{urlSec.envPostSave(p, configDir)}
	headerName := strings.TrimSpace(pr.ask("Auth header name (e.g. Authorization; empty = none)", ""))
	summary := "none"
	if headerName != "" {
		headerSec := askNotifierSecret(p, pr, deps.TokenReader,
			"auth header value (e.g. Bearer <token>)", webhookAuthHeaderEnvVar)
		headers = map[string]string{headerName: "env:" + headerSec.envVar}
		headerHooks = append(headerHooks, headerSec.envPostSave(p, configDir))
		summary = fmt.Sprintf("%s=env:%s", headerName, headerSec.envVar)
	}

	n := ensureNotify(cfg)
	verb := channelVerb(n.Webhook != nil)
	n.Webhook = &config.WebhookCfg{
		URL:      config.SecretRef("env:" + urlSec.envVar),
		Headers:  headers,
		Severity: sev,
	}
	changed := []string{fmt.Sprintf("notify.webhook — %s channel (severity=%s, url=env:%s, headers=%s)",
		verb, describeSeverity(sev), urlSec.envVar, summary)}
	return changed, chainPostSave(headerHooks...), nil
}
