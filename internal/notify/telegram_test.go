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

// captured holds one Telegram sendMessage request captured by the mock server.
type captured struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

// newTelegramMock returns an httptest server that captures all sendMessage POSTs.
func newTelegramMock(t *testing.T) (*httptest.Server, func() []captured) {
	t.Helper()
	var reqs []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		var c captured
		if err := json.Unmarshal(body, &c); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		reqs = append(reqs, c)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []captured {
		out := make([]captured, len(reqs))
		copy(out, reqs)
		return out
	}
}

func newTestTelegram(t *testing.T, srv *httptest.Server, chatIDs []string) *notify.TelegramNotifier {
	t.Helper()
	n := notify.NewTelegram("test-token", chatIDs)
	n.SetAPIBase(srv.URL) // test seam
	return n
}

// ── Basic send ────────────────────────────────────────────────────────────────

func TestTelegram_SendsToAllChatIDs(t *testing.T) {
	srv, captured := newTelegramMock(t)
	n := newTestTelegram(t, srv, []string{"111", "222"})

	msg := sdk.Notification{Severity: "warn", Title: "SSH brute-force detected"}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	got := captured()
	if len(got) != 2 {
		t.Fatalf("expected 2 posts (one per chat), got %d", len(got))
	}
	if got[0].ChatID != "111" || got[1].ChatID != "222" {
		t.Errorf("unexpected chat IDs: %v", got)
	}
	for _, c := range got {
		if c.ParseMode != "MarkdownV2" {
			t.Errorf("parse_mode must be MarkdownV2, got %q", c.ParseMode)
		}
		if !strings.Contains(c.Text, "EzyShield") {
			t.Errorf("text should mention EzyShield: %q", c.Text)
		}
	}
}

func TestTelegram_IncludesActionFields(t *testing.T) {
	srv, captured := newTelegramMock(t)
	n := newTestTelegram(t, srv, []string{"123"})

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

	text := captured()[0].Text
	// Dots in IPs and hyphens in reasons are escaped for MarkdownV2.
	for _, want := range []string{"1\\.2\\.3\\.4", "3", "24h0m0s", "SSH brute\\-force"} {
		if !strings.Contains(text, want) {
			t.Errorf("text should contain %q:\n%s", want, text)
		}
	}
}

func TestTelegram_SeverityEmoji(t *testing.T) {
	srv, captured := newTelegramMock(t)
	n := newTestTelegram(t, srv, []string{"1"})

	cases := []struct {
		sev   string
		emoji string
	}{
		{"critical", "🚨"},
		{"warn", "⚠"},
		{"info", "ℹ"},
	}
	for _, tc := range cases {
		t.Run(tc.sev, func(t *testing.T) {
			_ = n.Send(context.Background(), sdk.Notification{Severity: tc.sev, Title: "t"})
			got := captured()
			last := got[len(got)-1].Text
			if !strings.Contains(last, tc.emoji) {
				t.Errorf("expected emoji %q for severity %q in: %q", tc.emoji, tc.sev, last)
			}
		})
	}
}

// ── Security: MarkdownV2 injection ────────────────────────────────────────────

// TestTelegram_MDInjection feeds hostile log content that contains Telegram
// MarkdownV2 special characters and verifies they are all escaped so an attacker
// cannot inject formatted links, code blocks, or spoofed fields.
func TestTelegram_MDInjection(t *testing.T) {
	srv, captured := newTelegramMock(t)
	n := newTestTelegram(t, srv, []string{"1"})

	// Hostile payloads that an attacker might put in a log line's username/path.
	hostile := []string{
		`[click me](http://evil.example)`, // link injection
		"*bold*",                          // bold injection
		"`code`",                          // code injection
		"_italic_",                        // italic injection
		"[ADMIN] authorized",              // bracket injection
		"!\\/|{}#+-=~>.",                  // all other specials
	}
	for _, payload := range hostile {
		ip := netip.MustParseAddr("10.0.0.1")
		msg := sdk.Notification{
			Severity: "warn",
			Title:    payload,
			Action:   &sdk.Action{IP: ip, Reason: payload},
		}
		if err := n.Send(context.Background(), msg); err != nil {
			t.Fatalf("payload %q: send error: %v", payload, err)
		}
	}

	for _, c := range captured() {
		// After escaping, none of these patterns should appear unescaped in the text.
		forbiddenPatterns := []string{
			"[click me](", // unescaped link
			"*bold*",      // unescaped bold
			"`code`",      // unescaped code
		}
		for _, p := range forbiddenPatterns {
			if strings.Contains(c.Text, p) {
				t.Errorf("found unescaped pattern %q in Telegram message:\n%s", p, c.Text)
			}
		}
	}
}

// ── Field length cap ──────────────────────────────────────────────────────────

func TestTelegram_LongFieldTruncated(t *testing.T) {
	srv, captured := newTelegramMock(t)
	n := newTestTelegram(t, srv, []string{"1"})

	longReason := strings.Repeat("x", 2000)
	ip := netip.MustParseAddr("2.3.4.5")
	msg := sdk.Notification{
		Severity: "warn",
		Title:    "test",
		Action:   &sdk.Action{IP: ip, Reason: longReason},
	}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	// The full 2000-char reason must not appear in the sent text.
	text := captured()[0].Text
	if strings.Contains(text, longReason) {
		t.Error("2000-char reason was not truncated before sending to Telegram")
	}
	// The text should still be non-empty and contain the truncation marker.
	if !strings.Contains(text, "…") {
		t.Error("expected truncation ellipsis in Telegram message")
	}
}

// ── HTTP error handling ───────────────────────────────────────────────────────

func TestTelegram_HTTPErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	n := notify.NewTelegram("tok", []string{"1"})
	n.SetAPIBase(srv.URL)

	err := n.Send(context.Background(), sdk.Notification{Severity: "info", Title: "t"})
	if err == nil {
		t.Fatal("expected error on HTTP 500, got nil")
	}
}

func TestTelegram_Name(t *testing.T) {
	n := notify.NewTelegram("tok", []string{"1"})
	if n.Name() != "telegram" {
		t.Errorf("expected Name()=telegram, got %q", n.Name())
	}
}
