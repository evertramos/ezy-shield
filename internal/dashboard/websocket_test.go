package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// dialWS opens a websocket to base+"/dashboard/ws" carrying the cookie
// jar from client. The httptest TLS server uses a self-signed cert, so
// the websocket client is configured to share the same TLS config.
func dialWS(t *testing.T, client *http.Client, base string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	wsURL := "wss://" + strings.TrimPrefix(base, "https://") + "/dashboard/ws"
	opts := &websocket.DialOptions{
		HTTPClient: client,
	}
	return websocket.Dial(context.Background(), wsURL, opts)
}

func TestWebSocket_RequiresAuth(t *testing.T) {
	// newTestServer builds a bare server without a login flow: the client
	// has no session cookie so requireAuth must divert the upgrade to
	// /login instead of switching protocols.
	_, client, base, cleanup := newTestServer(t, "irrelevant")
	defer cleanup()

	conn, resp, err := dialWS(t, client, base)
	if conn != nil {
		_ = conn.CloseNow() //nolint:errcheck // test cleanup
	}
	if err == nil {
		t.Fatalf("expected dial to fail on unauth; got conn")
	}
	// coder/websocket surfaces the HTTP status on the returned response.
	// The requireAuth middleware issues 303 → /login; the ws library
	// treats anything other than 101 as an error.
	if resp == nil {
		t.Fatalf("expected an HTTP response even on failure, got nil")
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

func TestWebSocket_AuthedReceivesHello(t *testing.T) {
	// Build an authed session against a real Server (mock daemon offline
	// is fine — the ws path does not depend on daemon data at open time).
	dir := t.TempDir()
	srv, err := New(Config{
		Addr:       "127.0.0.1:0",
		AuthDBPath: filepath.Join(dir, "dashboard.db"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close() //nolint:errcheck // test cleanup
	hash, err := hashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := srv.store.setAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatalf("setAdmin: %v", err)
	}

	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	loginForm := url.Values{"username": {"admin"}, "password": {"correct-horse-battery-staple"}}
	if resp := doPostForm(t, client, ts.URL+"/login", loginForm); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status %d", resp.StatusCode)
	} else {
		closeBody(t, resp)
	}

	conn, resp, err := dialWS(t, client, ts.URL)
	if err != nil {
		t.Fatalf("ws dial: %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.CloseNow() }() //nolint:errcheck // test cleanup

	// The handler emits a "hello" frame immediately after upgrade.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	kind, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if kind != websocket.MessageText {
		t.Errorf("frame type = %v, want text", kind)
	}
	var env wsMessage
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("hello decode: %v", err)
	}
	if env.Type != "hello" {
		t.Errorf("first message = %q, want hello", env.Type)
	}
}

func TestEventsPage_LiveDaemon(t *testing.T) {
	entries := []daemon.EventEntry{
		{ID: 3, RecordedAt: "2026-07-08T02:00:00Z", Op: "allow_add", IP: "192.0.2.0/24", TTLSeconds: 0, Strike: 0, Reason: "office"},
		{ID: 2, RecordedAt: "2026-07-08T01:00:00Z", Op: "unban", IP: "203.0.113.1", TTLSeconds: 0, Strike: 0},
		{ID: 1, RecordedAt: "2026-07-08T00:00:00Z", Op: "ban", IP: "203.0.113.1", TTLSeconds: 300, Strike: 1, Reason: "sshd"},
	}
	md := newMockDaemon(t, func(req daemon.SocketRequest) daemon.SocketResponse {
		if req.Verb == "events" {
			raw, _ := json.Marshal(entries)
			return daemon.SocketResponse{OK: true, Data: raw}
		}
		return daemon.SocketResponse{OK: true, Data: json.RawMessage("[]")}
	})
	_, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := doGet(t, client, base+"/dashboard/events")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	for _, want := range []string{"192.0.2.0/24", "203.0.113.1", "allow_add", "unban", "ban", "sshd", "office"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestEventsPage_DaemonOffline(t *testing.T) {
	_, client, base, cleanup := newAuthedTestServer(t, "")
	defer cleanup()

	resp := doGet(t, client, base+"/dashboard/events")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "Daemon is offline") {
		t.Errorf("expected offline banner on the events page")
	}
}
