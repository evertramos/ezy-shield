package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// WebhookNotifier sends alert Notifications to an arbitrary HTTP endpoint as JSON.
// The URL is resolved from a SecretRef before construction; it is never stored in
// config files, logs, or error strings.
// Custom headers (e.g. Authorization, X-API-Key) are sent on every request;
// header values must not be logged or included in errors.
type WebhookNotifier struct {
	url     string
	headers map[string]string
	client  *http.Client
}

// NewWebhook constructs a WebhookNotifier.
// url is the already-resolved endpoint URL (not the env reference).
// headers is copied to avoid external mutation; values must be pre-resolved secrets.
func NewWebhook(url string, headers map[string]string) *WebhookNotifier {
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[k] = v
	}
	return &WebhookNotifier{
		url:     url,
		headers: h,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Name implements sdk.Notifier.
func (w *WebhookNotifier) Name() string { return "webhook" }

// SetWebhookURL overrides the endpoint URL. Used only in tests to point at an httptest server.
func (w *WebhookNotifier) SetWebhookURL(url string) { w.url = url }

// webhookPayload is the JSON body posted to the generic webhook endpoint.
// All fields come from the structured Notification, never from raw log lines.
type webhookPayload struct {
	Severity string         `json:"severity"`
	Title    string         `json:"title"`
	Body     string         `json:"body,omitempty"`
	Action   *webhookAction `json:"action,omitempty"`
}

type webhookAction struct {
	Op     string `json:"op"`
	IP     string `json:"ip,omitempty"`
	Strike int    `json:"strike,omitempty"`
	TTL    string `json:"ttl,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Send marshals msg as a JSON payload and POSTs it to the configured URL.
// Attacker-controlled content is length-capped before serialisation.
// Header values are never included in returned errors.
func (w *WebhookNotifier) Send(ctx context.Context, msg sdk.Notification) error {
	payload := buildWebhookPayload(msg)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: http: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: endpoint returned %d", resp.StatusCode)
	}
	return nil
}

func buildWebhookPayload(msg sdk.Notification) webhookPayload {
	p := webhookPayload{
		Severity: msg.Severity,
		Title:    capLen(msg.Title, maxFieldLen),
		Body:     capLen(msg.Body, maxFieldLen),
	}
	if a := msg.Action; a != nil {
		wa := &webhookAction{
			Op:     a.Op,
			Strike: a.Strike,
			Reason: capLen(a.Reason, maxFieldLen),
		}
		if a.IP.IsValid() {
			wa.IP = a.IP.String()
		}
		if a.TTL > 0 {
			wa.TTL = a.TTL.String()
		}
		p.Action = wa
	}
	return p
}
