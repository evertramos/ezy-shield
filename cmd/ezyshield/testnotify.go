// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// runTestNotify backs `test notifier <name>` (and its deprecated
// `test-notify` alias); the cobra wiring lives in testcmd.go.
func runTestNotify(cmd *cobra.Command, configDir, channel string) error {
	switch channel {
	case "telegram", "email", "slack", "discord", "webhook", "all":
	default:
		return fmt.Errorf("unknown channel %q: must be telegram, email, slack, discord, webhook, or all", channel)
	}

	cfgPath := filepath.Join(configDir, "config.yaml")
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.Notify == nil {
		return fmt.Errorf("no notify section in %s — add a notify: block to enable notifications", cfgPath)
	}

	testMsg := buildTestNotification(cmd.CommandPath())
	ctx := context.Background()
	sent := 0

	if (channel == "telegram" || channel == "all") && cfg.Notify.Telegram != nil {
		if err := sendTestTelegram(ctx, cmd, cfg.Notify.Telegram, testMsg); err != nil {
			return err
		}
		sent++
	}

	if (channel == "email" || channel == "all") && cfg.Notify.Email != nil {
		if err := sendTestEmail(ctx, cmd, cfg.Notify.Email, testMsg); err != nil {
			return err
		}
		sent++
	}

	// slack/discord/webhook were configurable (config notifier wizard, daemon)
	// but never testable, and `test notifier all` silently omitted them
	// (issue #356).
	if (channel == "slack" || channel == "all") && cfg.Notify.Slack != nil {
		if err := sendTestSlack(ctx, cmd, cfg.Notify.Slack, testMsg); err != nil {
			return err
		}
		sent++
	}

	if (channel == "discord" || channel == "all") && cfg.Notify.Discord != nil {
		if err := sendTestDiscord(ctx, cmd, cfg.Notify.Discord, testMsg); err != nil {
			return err
		}
		sent++
	}

	if (channel == "webhook" || channel == "all") && cfg.Notify.Webhook != nil {
		if err := sendTestWebhook(ctx, cmd, cfg.Notify.Webhook, testMsg); err != nil {
			return err
		}
		sent++
	}

	if sent == 0 {
		return fmt.Errorf("channel %q is not configured in %s", channel, cfgPath)
	}

	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), map[string]any{
			"channel": channel,
			"status":  "sent",
		})
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "test notification sent to %s\n", channel); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func sendTestTelegram(ctx context.Context, cmd *cobra.Command, tcfg *config.TelegramCfg, msg sdk.Notification) error {
	token, err := tcfg.BotToken.Resolve()
	if err != nil {
		return fmt.Errorf("telegram: resolving bot_token: %w", err)
	}
	n := notify.NewTelegram(token, tcfg.ChatIDs)
	if err := n.Send(ctx, msg); err != nil {
		return fmt.Errorf("telegram: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), "telegram: OK"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func sendTestEmail(ctx context.Context, cmd *cobra.Command, ecfg *config.EmailCfg, msg sdk.Notification) error {
	password, err := ecfg.Password.Resolve()
	if err != nil && ecfg.Username != "" {
		return fmt.Errorf("email: resolving password: %w", err)
	}
	n := notify.NewEmail(ecfg.From, ecfg.To, ecfg.Host, ecfg.Port, ecfg.Username, password, ecfg.TLS)
	if err := n.Send(ctx, msg); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), "email: OK"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func sendTestSlack(ctx context.Context, cmd *cobra.Command, scfg *config.SlackCfg, msg sdk.Notification) error {
	url, err := scfg.WebhookURL.Resolve()
	if err != nil {
		return fmt.Errorf("slack: resolving webhook_url: %w", err)
	}
	n := notify.NewSlack(url, scfg.Channel)
	if err := n.Send(ctx, msg); err != nil {
		return fmt.Errorf("slack: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), "slack: OK"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func sendTestDiscord(ctx context.Context, cmd *cobra.Command, dcfg *config.DiscordCfg, msg sdk.Notification) error {
	url, err := dcfg.WebhookURL.Resolve()
	if err != nil {
		return fmt.Errorf("discord: resolving webhook_url: %w", err)
	}
	n := notify.NewDiscord(url)
	if err := n.Send(ctx, msg); err != nil {
		return fmt.Errorf("discord: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), "discord: OK"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func sendTestWebhook(ctx context.Context, cmd *cobra.Command, wcfg *config.WebhookCfg, msg sdk.Notification) error {
	url, err := wcfg.URL.Resolve()
	if err != nil {
		return fmt.Errorf("webhook: resolving url: %w", err)
	}
	n := notify.NewWebhook(url, wcfg.Headers)
	if err := n.Send(ctx, msg); err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), "webhook: OK"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// buildTestNotification creates a synthetic alert that exercises all message
// fields. source is the invoking command path (derived, never hardcoded —
// e.g. "ezyshield test notifier").
func buildTestNotification(source string) sdk.Notification {
	ip := netip.MustParseAddr("192.0.2.1") // TEST-NET-1 per RFC 5737, safe for docs/tests
	return sdk.Notification{
		Severity: "warn",
		Title:    "EzyShield test notification",
		Body:     fmt.Sprintf("This is a test notification from '%s'. No action required.", source),
		Action: &sdk.Action{
			IP:     ip,
			Op:     "ban",
			Strike: 2,
			TTL:    time.Hour,
			Reason: "test: SSH brute-force simulation",
		},
	}
}
