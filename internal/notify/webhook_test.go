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

// webhookCaptured holds one generic webhook request.
type webhookCaptured struct {
	Header http.Header
	Body   struct {
		Severity string `json:"severity"`
		Title    string `json:"title"`
		Body     string `json:"body"`
		Action   *struct {
			Op     string `json:"op"`
			IP     string `json:"ip"`
			Strike int    `json:"strike"`
			TTL    string `json:"ttl"`
			Reason string `json:"reason"`
		} `json:"action"`
	}
}

func newWebhookMock(t *testing.T, statusCode int) (*httptest.Server, func() []webhookCaptured) {
	t.Helper()
	var reqs []webhookCaptured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		var c webhookCaptured
		c.Header = r.Header
		if err := json.Unmarshal(raw, &c.Body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		reqs = append(reqs, c)
		w.WriteHeader(statusCode)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []webhookCaptured {
		out := make([]webhookCaptured, len(reqs))
		copy(out, reqs)
		return out
	}
}

func newTestWebhook(t *testing.T, srv *httptest.Server, headers map[string]string) *notify.WebhookNotifier {
	t.Helper()
	n := notify.NewWebhook("http://placeholder", headers)
	n.SetWebhookURL(srv.URL)
	return n
}

// ── Basic send ────────────────────────────────────────────────────────────────

func TestWebhook_Send_basic(t *testing.T) {
	srv, captured := newWebhookMock(t, http.StatusOK)
	n := newTestWebhook(t, srv, nil)

	msg := sdk.Notification{Severity: "info", Title: "daemon started", Body: "all systems go"}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	got := captured()
	if len(got) != 1 {
		t.Fatalf("expected 1 request, got %d", len(got))
	}
	b := got[0].Body
	if b.Severity != "info" {
		t.Errorf("severity: expected info, got %q", b.Severity)
	}
	if b.Title != "daemon started" {
		t.Errorf("title: expected %q, got %q", "daemon started", b.Title)
	}
	if b.Body != "all systems go" {
		t.Errorf("body: expected %q, got %q", "all systems go", b.Body)
	}
	if b.Action != nil {
		t.Error("action should be nil when not set")
	}
}

func TestWebhook_Send_includesActionFields(t *testing.T) {
	srv, captured := newWebhookMock(t, http.StatusAccepted)
	n := newTestWebhook(t, srv, nil)

	ip := netip.MustParseAddr("5.6.7.8")
	msg := sdk.Notification{
		Severity: "critical",
		Title:    "IP banned",
		Action: &sdk.Action{
			IP:     ip,
			Op:     "ban",
			Strike: 4,
			TTL:    7 * 24 * time.Hour,
			Reason: "repeated scanner",
		},
	}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	a := captured()[0].Body.Action
	if a == nil {
		t.Fatal("expected action in payload")
	}
	if a.IP != "5.6.7.8" {
		t.Errorf("ip: expected 5.6.7.8, got %q", a.IP)
	}
	if a.Op != "ban" {
		t.Errorf("op: expected ban, got %q", a.Op)
	}
	if a.Strike != 4 {
		t.Errorf("strike: expected 4, got %d", a.Strike)
	}
	if a.Reason != "repeated scanner" {
		t.Errorf("reason: expected %q, got %q", "repeated scanner", a.Reason)
	}
	if a.TTL == "" {
		t.Error("ttl should be non-empty")
	}
}

func TestWebhook_Send_customHeaders(t *testing.T) {
	srv, captured := newWebhookMock(t, http.StatusOK)
	n := newTestWebhook(t, srv, map[string]string{
		"X-Api-Key": "secret-token",
		"X-Source":  "ezyshield",
	})

	if err := n.Send(context.Background(), sdk.Notification{Severity: "info", Title: "t"}); err != nil {
		t.Fatal(err)
	}

	got := captured()[0].Header
	if got.Get("X-Api-Key") != "secret-token" {
		t.Errorf("X-Api-Key header not set correctly")
	}
	if got.Get("X-Source") != "ezyshield" {
		t.Errorf("X-Source header not set correctly")
	}
	if got.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type should be application/json")
	}
}

// ── Field length cap ──────────────────────────────────────────────────────────

func TestWebhook_LongFieldTruncated(t *testing.T) {
	srv, captured := newWebhookMock(t, http.StatusOK)
	n := newTestWebhook(t, srv, nil)

	longReason := strings.Repeat("z", 2000)
	ip := netip.MustParseAddr("9.9.9.9")
	msg := sdk.Notification{
		Severity: "warn",
		Title:    "test",
		Action:   &sdk.Action{IP: ip, Reason: longReason},
	}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	a := captured()[0].Body.Action
	if a != nil && a.Reason == longReason {
		t.Error("2000-char reason was not truncated in webhook payload")
	}
}

// ── HTTP error handling ───────────────────────────────────────────────────────

func TestWebhook_HTTPErrorReturnsError(t *testing.T) {
	srv, _ := newWebhookMock(t, http.StatusInternalServerError)
	n := newTestWebhook(t, srv, nil)

	err := n.Send(context.Background(), sdk.Notification{Severity: "info", Title: "t"})
	if err == nil {
		t.Fatal("expected error on HTTP 500, got nil")
	}
}

func TestWebhook_2xxStatusCodes_succeed(t *testing.T) {
	for _, code := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv, _ := newWebhookMock(t, code)
			n := newTestWebhook(t, srv, nil)
			if err := n.Send(context.Background(), sdk.Notification{Severity: "info", Title: "t"}); err != nil {
				t.Errorf("expected success on HTTP %d, got %v", code, err)
			}
		})
	}
}

func TestWebhook_Name(t *testing.T) {
	n := notify.NewWebhook("http://placeholder", nil)
	if n.Name() != "webhook" {
		t.Errorf("expected Name()=webhook, got %q", n.Name())
	}
}

// TestWebhook_HeaderMutationIsolated verifies that mutating headers after
// construction does not affect the notifier's internal copy.
func TestWebhook_HeaderMutationIsolated(t *testing.T) {
	srv, captured := newWebhookMock(t, http.StatusOK)
	headers := map[string]string{"X-Test": "original"}
	n := newTestWebhook(t, srv, headers)
	headers["X-Test"] = "mutated" // mutate caller's map

	if err := n.Send(context.Background(), sdk.Notification{Severity: "info", Title: "t"}); err != nil {
		t.Fatal(err)
	}
	if got := captured()[0].Header.Get("X-Test"); got != "original" {
		t.Errorf("expected X-Test=original (isolated copy), got %q", got)
	}
}
