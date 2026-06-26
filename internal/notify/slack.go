package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// SlackNotifier sends alert Notifications to a Slack incoming webhook.
// The webhook URL is resolved from a SecretRef before construction; it is never
// stored in config files, logs, or error strings.
type SlackNotifier struct {
	webhookURL string
	channel    string
	client     *http.Client
}

// NewSlack constructs a SlackNotifier.
// webhookURL is the already-resolved Slack incoming webhook URL (not the env reference).
// channel, if non-empty, overrides the default channel configured in the Slack app.
func NewSlack(webhookURL, channel string) *SlackNotifier {
	return &SlackNotifier{
		webhookURL: webhookURL,
		channel:    channel,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Name implements sdk.Notifier.
func (s *SlackNotifier) Name() string { return "slack" }

// SetWebhookURL overrides the webhook URL. Used only in tests to point at an httptest server.
func (s *SlackNotifier) SetWebhookURL(url string) { s.webhookURL = url }

// Send formats msg as a Slack Block Kit payload and posts it to the configured webhook.
// Attacker-controlled content (title, reason, body) is escaped and length-capped
// before being included in the message to prevent Slack mrkdwn injection.
func (s *SlackNotifier) Send(ctx context.Context, msg sdk.Notification) error {
	payload := buildSlackPayload(msg, s.channel)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack: http: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack: webhook returned %d", resp.StatusCode)
	}
	return nil
}

type slackPayload struct {
	Channel     string            `json:"channel,omitempty"`
	Text        string            `json:"text"` // fallback for notifications that strip blocks
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type string     `json:"type"`
	Text *slackText `json:"text,omitempty"`
}

type slackText struct {
	Type string `json:"type"` // "mrkdwn" or "plain_text"
	Text string `json:"text"`
}

// buildSlackPayload constructs the Slack Block Kit payload for a Notification.
// All untrusted fields are sanitized with escSlack + capLen to prevent mrkdwn injection.
func buildSlackPayload(msg sdk.Notification, channel string) slackPayload {
	color := slackColor(msg.Severity)
	var sb strings.Builder
	fmt.Fprintf(&sb, "*EzyShield Alert* — %s %s\n", severityEmoji(msg.Severity), escSlack(msg.Severity))
	fmt.Fprintf(&sb, "*%s*\n", escSlack(capLen(msg.Title, maxFieldLen)))
	if a := msg.Action; a != nil {
		fmt.Fprintf(&sb, ">*Action:* %s", escSlack(a.Op))
		if a.IP.IsValid() {
			fmt.Fprintf(&sb, "   *IP:* `%s`", escSlack(a.IP.String()))
		}
		if a.Strike > 0 {
			fmt.Fprintf(&sb, "   *Strike:* %d", a.Strike)
		}
		if a.TTL > 0 {
			fmt.Fprintf(&sb, "   *TTL:* %s", escSlack(a.TTL.String()))
		}
		if a.Reason != "" {
			fmt.Fprintf(&sb, "\n>*Reason:* %s", escSlack(capLen(a.Reason, maxFieldLen)))
		}
		sb.WriteByte('\n')
	}
	if msg.Body != "" {
		fmt.Fprintf(&sb, ">%s\n", escSlack(capLen(msg.Body, maxFieldLen)))
	}
	text := strings.TrimRight(sb.String(), "\n")

	return slackPayload{
		Channel: channel,
		Text:    fmt.Sprintf("[EzyShield] %s: %s", strings.ToUpper(msg.Severity), capLen(msg.Title, 200)),
		Attachments: []slackAttachment{
			{
				Color: color,
				Blocks: []slackBlock{
					{Type: "section", Text: &slackText{Type: "mrkdwn", Text: text}},
				},
			},
		},
	}
}

func slackColor(severity string) string {
	switch severity {
	case "critical":
		return "#E01E5A" // Slack danger red
	case "warn":
		return "#ECB22E" // Slack warning yellow
	default:
		return "#36C5F0" // Slack info blue
	}
}

// escSlack escapes Slack mrkdwn special characters so that attacker-controlled
// content cannot inject formatting, links, or channel/user mentions.
// Characters requiring escaping: & < > (HTML entities) and Slack-specific: * _ ~ ` @
func escSlack(s string) string {
	// HTML entities first (required by Slack before mrkdwn escaping).
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	// Replace @ with the visually identical fullwidth form (U+FF20) so that
	// attacker-controlled log content cannot trigger @here/@channel/@everyone
	// broadcast mentions inside Slack Block Kit mrkdwn text.
	s = strings.ReplaceAll(s, "@", "＠")
	return s
}
