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

// DiscordNotifier sends alert Notifications to a Discord webhook using embed formatting.
// The webhook URL is resolved from a SecretRef before construction; it is never
// stored in config files, logs, or error strings.
type DiscordNotifier struct {
	webhookURL string
	client     *http.Client
}

// NewDiscord constructs a DiscordNotifier.
// webhookURL is the already-resolved Discord webhook URL (not the env reference).
func NewDiscord(webhookURL string) *DiscordNotifier {
	return &DiscordNotifier{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Name implements sdk.Notifier.
func (d *DiscordNotifier) Name() string { return "discord" }

// SetWebhookURL overrides the webhook URL. Used only in tests to point at an httptest server.
func (d *DiscordNotifier) SetWebhookURL(url string) { d.webhookURL = url }

// Send formats msg as a Discord embed payload and posts it to the configured webhook.
// Attacker-controlled content (title, reason, body) is length-capped before being
// included in the embed to stay within Discord's field length limits (1024 chars).
func (d *DiscordNotifier) Send(ctx context.Context, msg sdk.Notification) error {
	payload := buildDiscordPayload(msg)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("discord: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("discord: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("discord: http: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	// Discord returns 204 No Content on success for webhook messages.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("discord: webhook returned %d", resp.StatusCode)
	}
	return nil
}

type discordPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields,omitempty"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// discordMaxField is Discord's limit for embed field values.
const discordMaxField = 1024

// buildDiscordPayload constructs the Discord embed payload for a Notification.
// All untrusted fields are length-capped to Discord's API limits.
func buildDiscordPayload(msg sdk.Notification) discordPayload {
	title := fmt.Sprintf("%s EzyShield Alert — %s", severityEmoji(msg.Severity), strings.ToUpper(msg.Severity))
	desc := capLen(msg.Title, maxFieldLen)

	var fields []discordField
	if a := msg.Action; a != nil {
		if a.Op != "" {
			fields = append(fields, discordField{Name: "Action", Value: capLen(a.Op, discordMaxField), Inline: true})
		}
		if a.IP.IsValid() {
			fields = append(fields, discordField{Name: "IP", Value: a.IP.String(), Inline: true})
		}
		if a.Strike > 0 {
			fields = append(fields, discordField{Name: "Strike", Value: fmt.Sprintf("%d", a.Strike), Inline: true})
		}
		if a.TTL > 0 {
			fields = append(fields, discordField{Name: "TTL", Value: a.TTL.String(), Inline: true})
		}
		if a.Reason != "" {
			fields = append(fields, discordField{Name: "Reason", Value: capLen(a.Reason, discordMaxField), Inline: false})
		}
	}
	if msg.Body != "" {
		fields = append(fields, discordField{Name: "Details", Value: capLen(msg.Body, discordMaxField), Inline: false})
	}

	return discordPayload{
		Embeds: []discordEmbed{
			{
				Title:       title,
				Description: desc,
				Color:       discordColor(msg.Severity),
				Fields:      fields,
			},
		},
	}
}

// discordColor returns a Discord embed color integer for a severity level.
// Discord colors are decimal representations of 0xRRGGBB.
func discordColor(severity string) int {
	switch severity {
	case "critical":
		return 0xED4245 // Discord red
	case "warn":
		return 0xFEE75C // Discord yellow
	default:
		return 0x5865F2 // Discord blurple (info)
	}
}
