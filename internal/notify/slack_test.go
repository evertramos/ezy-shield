package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// slackCaptured holds one Slack webhook request body.
type slackCaptured struct {
	Text        string `json:"text"`
	Channel     string `json:"channel"`
	Attachments []struct {
		Color  string `json:"color"`
		Blocks []struct {
			Type string `json:"type"`
			Text *struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"text"`
		} `json:"blocks"`
	} `json:"attachments"`
}

func newSlackMock(t *testing.T) (*httptest.Server, func() []slackCaptured) {
	t.Helper()
	var reqs []slackCaptured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		var c slackCaptured
		if err := json.Unmarshal(body, &c); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		reqs = append(reqs, c)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []slackCaptured {
		out := make([]slackCaptured, len(reqs))
		copy(out, reqs)
		return out
	}
}

func newTestSlack(t *testing.T, srv *httptest.Server, channel string) *notify.SlackNotifier {
	t.Helper()
	n := notify.NewSlack("http://placeholder", channel)
	n.SetWebhookURL(srv.URL)
	return n
}

// ── Basic send ────────────────────────────────────────────────────────────────

func TestSlack_Send_basic(t *testing.T) {
	srv, captured := newSlackMock(t)
	n := newTestSlack(t, srv, "")

	msg := sdk.Notification{Severity: "warn", Title: "SSH brute-force detected"}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	got := captured()
	if len(got) != 1 {
		t.Fatalf("expected 1 request, got %d", len(got))
	}
	req := got[0]
	if !strings.Contains(req.Text, "SSH brute-force detected") {
		t.Errorf("fallback text should contain title, got: %q", req.Text)
	}
	if len(req.Attachments) == 0 {
		t.Fatal("expected at least one attachment")
	}
	att := req.Attachments[0]
	if att.Color == "" {
		t.Error("attachment should have a color")
	}
	if len(att.Blocks) == 0 {
		t.Error("attachment should have blocks")
	}
}

func TestSlack_Send_includesActionFields(t *testing.T) {
	srv, captured := newSlackMock(t)
	n := newTestSlack(t, srv, "")

	ip := netip.MustParseAddr("1.2.3.4")
	msg := sdk.Notification{
		Severity: "critical",
		Title:    "IP banned",
		Action: &sdk.Action{
			IP:     ip,
			Op:     "ban",
			Strike: 3,
			TTL:    24 * time.Hour,
			Reason: "SSH brute-force",
		},
	}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	got := captured()
	if len(got) == 0 {
		t.Fatal("no request captured")
	}
	blockText := got[0].Attachments[0].Blocks[0].Text.Text
	for _, want := range []string{"1.2.3.4", "ban", "SSH brute-force", "3"} {
		if !strings.Contains(blockText, want) {
			t.Errorf("block text should contain %q:\n%s", want, blockText)
		}
	}
}

func TestSlack_Send_channelOverride(t *testing.T) {
	srv, captured := newSlackMock(t)
	n := newTestSlack(t, srv, "#security")

	if err := n.Send(context.Background(), sdk.Notification{Severity: "info", Title: "test"}); err != nil {
		t.Fatal(err)
	}

	if got := captured()[0].Channel; got != "#security" {
		t.Errorf("expected channel #security, got %q", got)
	}
}

func TestSlack_Send_severityColors(t *testing.T) {
	cases := []struct {
		sev   string
		color string
	}{
		{"critical", "#E01E5A"},
		{"warn", "#ECB22E"},
		{"info", "#36C5F0"},
	}
	for _, tc := range cases {
		t.Run(tc.sev, func(t *testing.T) {
			srv, captured := newSlackMock(t)
			n := newTestSlack(t, srv, "")
			_ = n.Send(context.Background(), sdk.Notification{Severity: tc.sev, Title: "t"})
			got := captured()
			if len(got) == 0 || len(got[0].Attachments) == 0 {
				t.Fatal("no attachment")
			}
			if got[0].Attachments[0].Color != tc.color {
				t.Errorf("severity %q: expected color %q, got %q", tc.sev, tc.color, got[0].Attachments[0].Color)
			}
		})
	}
}

// ── Security: mrkdwn injection ────────────────────────────────────────────────

// TestSlack_MrkdwnInjection feeds hostile log content and verifies & < > and
// @ are escaped so an attacker cannot inject Slack API commands, links, or
// broadcast mentions (@here / @channel / @everyone) via attacker-controlled
// fields (title, reason, body).
func TestSlack_MrkdwnInjection(t *testing.T) {
	srv, captured := newSlackMock(t)
	n := newTestSlack(t, srv, "")

	hostile := []string{
		"<http://evil.example|click me>", // Slack link injection
		"&amp; encoded entity",           // double-encoding check
		"<script>alert(1)</script>",      // XSS-style injection
		"@here notify all online",        // broadcast ping
		"@channel wake everyone up",      // broadcast ping
		"@everyone workspace-wide",       // broadcast ping
	}
	for _, payload := range hostile {
		msg := sdk.Notification{
			Severity: "warn",
			Title:    payload,
			Body:     payload,
			Action:   &sdk.Action{Reason: payload},
		}
		if err := n.Send(context.Background(), msg); err != nil {
			t.Fatalf("payload %q: send error: %v", payload, err)
		}
	}

	for i, c := range captured() {
		blockText := c.Attachments[0].Blocks[0].Text.Text
		// Unescaped < and > would allow Slack link/mention injection.
		if strings.Contains(blockText, "<http://") {
			t.Errorf("req %d: found unescaped Slack link in message:\n%s", i, blockText)
		}
		if strings.Contains(blockText, "<script>") {
			t.Errorf("req %d: found unescaped <script> in message:\n%s", i, blockText)
		}
		// Unescaped @ triggers broadcast notifications in Slack channels.
		for _, mention := range []string{"@here", "@channel", "@everyone"} {
			if strings.Contains(blockText, mention) {
				t.Errorf("req %d: found unescaped %q mention in message:\n%s", i, mention, blockText)
			}
		}
	}
}

// ── Field length cap ──────────────────────────────────────────────────────────

func TestSlack_LongFieldTruncated(t *testing.T) {
	srv, captured := newSlackMock(t)
	n := newTestSlack(t, srv, "")

	longTitle := strings.Repeat("x", 2000)
	if err := n.Send(context.Background(), sdk.Notification{Severity: "info", Title: longTitle}); err != nil {
		t.Fatal(err)
	}

	blockText := captured()[0].Attachments[0].Blocks[0].Text.Text
	if strings.Contains(blockText, longTitle) {
		t.Error("2000-char title was not truncated")
	}
	if !strings.Contains(blockText, "…") {
		t.Error("expected truncation ellipsis")
	}
}

// ── HTTP error handling ───────────────────────────────────────────────────────

func TestSlack_HTTPErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	n := notify.NewSlack("http://placeholder", "")
	n.SetWebhookURL(srv.URL)

	err := n.Send(context.Background(), sdk.Notification{Severity: "info", Title: "t"})
	if err == nil {
		t.Fatal("expected error on HTTP 400, got nil")
	}
}

func TestSlack_Name(t *testing.T) {
	n := notify.NewSlack("http://placeholder", "")
	if n.Name() != "slack" {
		t.Errorf("expected Name()=slack, got %q", n.Name())
	}
}
