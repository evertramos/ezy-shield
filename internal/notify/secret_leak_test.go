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
	"strconv"
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

// TestSecretLeak_BuildRequestError reproduces the review finding on #389:
// a secret containing a control character (e.g. a trailing CR from a
// CRLF-saved env file — SecretRef.Resolve() does not trim) makes
// http.NewRequestWithContext fail with a *url.Error whose Error() embeds the
// ENTIRE raw URL, secret included. The "build request" error path must be
// redacted just like the client.Do path. No network I/O occurs: the request
// never gets built.
func TestSecretLeak_BuildRequestError(t *testing.T) {
	crToken := leakBotToken + "\r"
	crKey := leakWebhookKey + "\r"
	msg := sdk.Notification{Severity: "warn", Title: "t"}

	t.Run("telegram", func(t *testing.T) {
		n := NewTelegram(crToken, []string{"42"})
		assertNoSecret(t, n.Send(context.Background(), msg), leakBotToken)
	})
	t.Run("discord", func(t *testing.T) {
		n := NewDiscord("https://discord.example/api/webhooks/1234/" + crKey)
		assertNoSecret(t, n.Send(context.Background(), msg), leakWebhookKey)
	})
	t.Run("slack", func(t *testing.T) {
		n := NewSlack("https://hooks.slack.example/services/T0000/B0000/"+crKey, "")
		assertNoSecret(t, n.Send(context.Background(), msg), leakWebhookKey)
	})
	t.Run("webhook", func(t *testing.T) {
		n := NewWebhook("https://hooks.internal.example/hook?key="+crKey, nil)
		assertNoSecret(t, n.Send(context.Background(), msg), leakWebhookKey)
	})
}

// TestSecretLeak_GenericWebhookResolvedAddrRedacted reproduces the second
// review finding on #389: for a RESOLVABLE secret host, Go's dial error names
// only the resolved IP, never the hostname ("dial tcp 127.0.0.1:33413:
// connect: connection refused"), so a hostname-based scrub misses it and the
// address survives into logs. For keepHost=false neither the hostname, nor
// the resolved address, nor the port may appear in the error chain.
// Loopback only — no network I/O leaves the host.
func TestSecretLeak_GenericWebhookResolvedAddrRedacted(t *testing.T) {
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving closed port: %v", err)
	}
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close() // port now refuses connections

	// "localhost" resolves (to 127.0.0.1 and/or ::1) but the port is closed,
	// so client.Do fails with a dial error naming the resolved IP:port.
	n := NewWebhook("http://localhost:"+port+"/hook?key="+leakWebhookKey, nil)

	err = n.Send(context.Background(), sdk.Notification{Severity: "warn", Title: "t"})
	if err == nil {
		t.Fatal("expected a transport error")
	}
	for _, leak := range []string{leakWebhookKey, "localhost", "127.0.0.1", "::1", port} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("keepHost=false error must not contain %q, got:\n  %v", leak, err)
		}
	}
}

// TestSecretLeak_GenericWebhookHostRedacted verifies that for a generic
// webhook the HOST is also stripped from transport errors — an operator's
// webhook host can itself be secret (internal name or capability host), unlike
// the well-known public API hosts of Telegram/Slack/Discord (Strix review of
// #319, folded into #360).
func TestSecretLeak_GenericWebhookHostRedacted(t *testing.T) {
	secretHost := "secret-internal-host.example"
	// Point at a closed port on that host name won't resolve; use a literal
	// unroutable address but assert the error text carries neither.
	n := NewWebhook("http://"+secretHost+"/hook?key="+leakWebhookKey, nil)

	err := n.Send(context.Background(), sdk.Notification{Severity: "warn", Title: "t"})
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), secretHost) {
		t.Errorf("generic webhook host must be redacted, leaked:\n  %v", err)
	}
	assertNoSecret(t, err, leakWebhookKey)
}
