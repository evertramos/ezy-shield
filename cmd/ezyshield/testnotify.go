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

func newTestNotifyCmd() *cobra.Command {
	var configDir string

	cmd := &cobra.Command{
		Use:   "test-notify <channel>",
		Short: "Send a test notification to a configured channel",
		Long: `Send a synthetic EzyShield alert to verify that a notification channel
is correctly configured.

<channel> must be one of: telegram, email, all

The command loads notify configuration from --config-dir/config.yaml,
resolves secrets from the environment variables declared in bot_token/password,
and sends a test ban notification. Exit code is non-zero on failure.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTestNotify(cmd, configDir, args[0])
		},
	}

	cmd.Flags().StringVar(&configDir, "config-dir", "/etc/ezyshield",
		"directory containing config.yaml")

	return cmd
}

func runTestNotify(cmd *cobra.Command, configDir, channel string) error {
	switch channel {
	case "telegram", "email", "all":
	default:
		return fmt.Errorf("unknown channel %q: must be telegram, email, or all", channel)
	}

	cfgPath := filepath.Join(configDir, "config.yaml")
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.Notify == nil {
		return fmt.Errorf("no notify section in %s — add a notify: block to enable notifications", cfgPath)
	}

	testMsg := buildTestNotification()
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

// buildTestNotification creates a synthetic alert that exercises all message fields.
func buildTestNotification() sdk.Notification {
	ip := netip.MustParseAddr("192.0.2.1") // TEST-NET-1 per RFC 5737, safe for docs/tests
	return sdk.Notification{
		Severity: "warn",
		Title:    "EzyShield test notification",
		Body:     "This is a test notification from 'ezyshield test-notify'. No action required.",
		Action: &sdk.Action{
			IP:     ip,
			Op:     "ban",
			Strike: 2,
			TTL:    time.Hour,
			Reason: "test: SSH brute-force simulation",
		},
	}
}
