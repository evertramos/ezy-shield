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

// discordCaptured holds one Discord webhook request body.
type discordCaptured struct {
	Embeds []struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Color       int    `json:"color"`
		Fields      []struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Inline bool   `json:"inline"`
		} `json:"fields"`
	} `json:"embeds"`
}

func newDiscordMock(t *testing.T) (*httptest.Server, func() []discordCaptured) {
	t.Helper()
	var reqs []discordCaptured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		var c discordCaptured
		if err := json.Unmarshal(body, &c); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		reqs = append(reqs, c)
		w.WriteHeader(http.StatusNoContent) // Discord returns 204
	}))
	t.Cleanup(srv.Close)
	return srv, func() []discordCaptured {
		out := make([]discordCaptured, len(reqs))
		copy(out, reqs)
		return out
	}
}

func newTestDiscord(t *testing.T, srv *httptest.Server) *notify.DiscordNotifier {
	t.Helper()
	n := notify.NewDiscord("http://placeholder")
	n.SetWebhookURL(srv.URL)
	return n
}

// ── Basic send ────────────────────────────────────────────────────────────────

func TestDiscord_Send_basic(t *testing.T) {
	srv, captured := newDiscordMock(t)
	n := newTestDiscord(t, srv)

	msg := sdk.Notification{Severity: "warn", Title: "SSH brute-force detected"}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	got := captured()
	if len(got) != 1 {
		t.Fatalf("expected 1 request, got %d", len(got))
	}
	embed := got[0].Embeds[0]
	if !strings.Contains(embed.Title, "EzyShield Alert") {
		t.Errorf("embed title should mention EzyShield, got: %q", embed.Title)
	}
	if !strings.Contains(embed.Description, "SSH brute-force detected") {
		t.Errorf("embed description should contain title, got: %q", embed.Description)
	}
	if embed.Color == 0 {
		t.Error("embed should have a non-zero color")
	}
}

func TestDiscord_Send_includesActionFields(t *testing.T) {
	srv, captured := newDiscordMock(t)
	n := newTestDiscord(t, srv)

	ip := netip.MustParseAddr("10.0.0.1")
	msg := sdk.Notification{
		Severity: "critical",
		Title:    "IP banned",
		Action: &sdk.Action{
			IP:     ip,
			Op:     "ban",
			Strike: 2,
			TTL:    1 * time.Hour,
			Reason: "Port scan",
		},
	}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	embed := captured()[0].Embeds[0]
	fieldNames := make(map[string]string)
	for _, f := range embed.Fields {
		fieldNames[f.Name] = f.Value
	}
	checks := map[string]string{
		"Action": "ban",
		"IP":     "10.0.0.1",
		"Strike": "2",
		"Reason": "Port scan",
	}
	for name, want := range checks {
		if got, ok := fieldNames[name]; !ok || !strings.Contains(got, want) {
			t.Errorf("field %q: expected %q, got %q", name, want, got)
		}
	}
}

func TestDiscord_Send_severityColors(t *testing.T) {
	cases := []struct {
		sev   string
		color int
	}{
		{"critical", 0xED4245},
		{"warn", 0xFEE75C},
		{"info", 0x5865F2},
	}
	for _, tc := range cases {
		t.Run(tc.sev, func(t *testing.T) {
			srv, captured := newDiscordMock(t)
			n := newTestDiscord(t, srv)
			_ = n.Send(context.Background(), sdk.Notification{Severity: tc.sev, Title: "t"})
			got := captured()
			if len(got) == 0 || len(got[0].Embeds) == 0 {
				t.Fatal("no embed")
			}
			if got[0].Embeds[0].Color != tc.color {
				t.Errorf("severity %q: expected color %d, got %d", tc.sev, tc.color, got[0].Embeds[0].Color)
			}
		})
	}
}

// ── Field length cap ──────────────────────────────────────────────────────────

func TestDiscord_LongFieldTruncated(t *testing.T) {
	srv, captured := newDiscordMock(t)
	n := newTestDiscord(t, srv)

	ip := netip.MustParseAddr("3.3.3.3")
	longReason := strings.Repeat("y", 2000)
	msg := sdk.Notification{
		Severity: "warn",
		Title:    "test",
		Action:   &sdk.Action{IP: ip, Reason: longReason},
	}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	embed := captured()[0].Embeds[0]
	for _, f := range embed.Fields {
		if f.Name == "Reason" && strings.Contains(f.Value, longReason) {
			t.Error("2000-char reason was not truncated in Discord field")
		}
	}
}

// ── HTTP error handling ───────────────────────────────────────────────────────

func TestDiscord_HTTPErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	n := notify.NewDiscord("http://placeholder")
	n.SetWebhookURL(srv.URL)

	err := n.Send(context.Background(), sdk.Notification{Severity: "info", Title: "t"})
	if err == nil {
		t.Fatal("expected error on HTTP 429, got nil")
	}
}

func TestDiscord_Name(t *testing.T) {
	n := notify.NewDiscord("http://placeholder")
	if n.Name() != "discord" {
		t.Errorf("expected Name()=discord, got %q", n.Name())
	}
}
