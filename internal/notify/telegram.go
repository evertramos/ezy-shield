package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	telegramAPIBase = "https://api.telegram.org"
	// maxFieldLen caps attacker-controlled content before forwarding to Telegram
	// to prevent message-size attacks and limit exposure of hostile log content.
	maxFieldLen = 512
)

// TelegramNotifier sends alert Notifications via the Telegram Bot API.
// The bot token is resolved from a SecretRef before construction; it is never
// stored in any config file, log, or error string.
type TelegramNotifier struct {
	token   string
	chatIDs []string
	client  *http.Client
	// apiBase is overridable in tests to point at an httptest server.
	apiBase string
}

// NewTelegram constructs a TelegramNotifier.
// token is the already-resolved bot token value (not the env reference).
func NewTelegram(token string, chatIDs []string) *TelegramNotifier {
	return &TelegramNotifier{
		token:   token,
		chatIDs: chatIDs,
		client:  &http.Client{Timeout: 10 * time.Second},
		apiBase: telegramAPIBase,
	}
}

// Name implements sdk.Notifier.
func (t *TelegramNotifier) Name() string { return "telegram" }

// SetAPIBase overrides the Telegram API base URL. Used only in tests to point
// at an httptest server; never call this in production code.
func (t *TelegramNotifier) SetAPIBase(base string) { t.apiBase = base }

// Send formats msg as MarkdownV2 and posts it to every configured chat ID.
// Attacker-controlled content (IP, reason, body) is escaped and length-capped
// before being included in the message.
func (t *TelegramNotifier) Send(ctx context.Context, msg sdk.Notification) error {
	text := formatTelegramMessage(msg)
	var errs []string
	for _, chatID := range t.chatIDs {
		if err := t.post(ctx, chatID, text); err != nil {
			errs = append(errs, fmt.Sprintf("chat %s: %v", chatID, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("telegram: %s", strings.Join(errs, "; "))
	}
	return nil
}

type telegramSendMsg struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

func (t *TelegramNotifier) post(ctx context.Context, chatID, text string) error {
	body, err := json.Marshal(telegramSendMsg{
		ChatID:    chatID,
		Text:      text,
		ParseMode: "MarkdownV2",
	})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	// The bot token appears only in the URL path, never in request body or logs.
	url := fmt.Sprintf("%s/bot%s/sendMessage", t.apiBase, t.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned %d", resp.StatusCode)
	}
	return nil
}

// formatTelegramMessage renders a MarkdownV2 message.
// All untrusted fields (IP, reason, body) go through escMD + capLen so that
// an attacker cannot inject Telegram formatting directives or oversized payloads.
func formatTelegramMessage(msg sdk.Notification) string {
	var sb strings.Builder
	sb.WriteString(severityEmoji(msg.Severity))
	sb.WriteString(" *EzyShield Alert*\n")
	sb.WriteString("\n*Severity*: ")
	sb.WriteString(escMD(msg.Severity))
	sb.WriteString("\n*Title*: ")
	sb.WriteString(escMD(capLen(msg.Title, maxFieldLen)))
	if a := msg.Action; a != nil {
		sb.WriteString("\n*Action*: ")
		sb.WriteString(escMD(a.Op))
		if a.IP.IsValid() {
			sb.WriteString("\n*IP*: `")
			sb.WriteString(escMD(a.IP.String()))
			sb.WriteString("`")
		}
		if a.Strike > 0 {
			sb.WriteString("\n*Strike*: ")
			sb.WriteString(escMD(fmt.Sprintf("%d", a.Strike)))
		}
		if a.TTL > 0 {
			sb.WriteString("\n*TTL*: ")
			sb.WriteString(escMD(a.TTL.String()))
		}
		if a.Reason != "" {
			sb.WriteString("\n*Reason*: ")
			sb.WriteString(escMD(capLen(a.Reason, maxFieldLen)))
		}
	}
	if msg.Body != "" {
		sb.WriteString("\n*Details*: ")
		sb.WriteString(escMD(capLen(msg.Body, maxFieldLen)))
	}
	return sb.String()
}

func severityEmoji(sev string) string {
	switch sev {
	case "critical":
		return "\U0001f6a8" // 🚨
	case "warn":
		return "⚠️" // ⚠️
	default:
		return "ℹ️" // ℹ️
	}
}

// escMD escapes all Telegram MarkdownV2 special characters so that
// attacker-controlled content cannot inject formatting or links.
// Spec: https://core.telegram.org/bots/api#markdownv2-style
func escMD(s string) string {
	const specials = `_*[]()~` + "`" + `>#+-=|{}.!\`
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		if strings.ContainsRune(specials, r) {
			sb.WriteByte('\\')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// capLen truncates s to at most maxBytes, stepping back to a valid UTF-8
// rune boundary and appending an ellipsis when truncated.
func capLen(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	b := maxBytes
	for b > 0 && !utf8.RuneStart(s[b]) {
		b--
	}
	return s[:b] + "…"
}
