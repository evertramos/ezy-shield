// Package notify — secret-leak gate tests (SECURITY-REVIEW §4, Hard Rule 3).
//
// Issue #319: http.Client.Do always returns *url.Error, whose Error() embeds
// the full request URL. For Telegram the bot token is a URL path segment; for
// Slack/Discord/generic webhooks the whole URL is a secret capability. These
// tests force a transport-level failure and assert the secret never appears in
// the returned error chain. They are a mandatory CI gate — do not delete.
package notify

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// Fixture-only secrets — clearly fake, never real credentials (Hard Rule 3).
const (
	leakBotToken   = "1234567890:TEST-FAKE-BOT-TOKEN-e5f6"
	leakWebhookKey = "TEST-FAKE-WEBHOOK-SECRET-a1b2"
)

// closedPortURL returns an http URL on 127.0.0.1 with a port that was just
// released, so every request fails with a transport-level *url.Error
// (connection refused) without any network I/O leaving the host.
func closedPortURL(t *testing.T, path string) string {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving closed port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr + path
}

func assertNoSecret(t *testing.T, err error, secret string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a transport error, got nil")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("secret leaked into error string (Hard Rule 3):\n  %v", err)
	}
}

func TestSecretLeak_TelegramTransportError(t *testing.T) {
	n := NewTelegram(leakBotToken, []string{"42"})
	n.SetAPIBase(closedPortURL(t, ""))

	err := n.Send(context.Background(), sdk.Notification{Severity: "warn", Title: "t"})
	assertNoSecret(t, err, leakBotToken)
}

func TestSecretLeak_DiscordTransportError(t *testing.T) {
	n := NewDiscord(closedPortURL(t, "/api/webhooks/1234/"+leakWebhookKey))

	err := n.Send(context.Background(), sdk.Notification{Severity: "warn", Title: "t"})
	assertNoSecret(t, err, leakWebhookKey)
}

func TestSecretLeak_SlackTransportError(t *testing.T) {
	n := NewSlack(closedPortURL(t, "/services/T0000/B0000/"+leakWebhookKey), "")

	err := n.Send(context.Background(), sdk.Notification{Severity: "warn", Title: "t"})
	assertNoSecret(t, err, leakWebhookKey)
}

func TestSecretLeak_GenericWebhookTransportError(t *testing.T) {
	n := NewWebhook(closedPortURL(t, "/hook?key="+leakWebhookKey), nil)

	err := n.Send(context.Background(), sdk.Notification{Severity: "warn", Title: "t"})
	assertNoSecret(t, err, leakWebhookKey)
}
