package dashboard

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// mockDaemon spins up a unix-socket server that answers the same verbs the
// real daemon does. Tests hand it a scripted response per verb and can
// inspect the requests it received afterwards.
type mockDaemon struct {
	sockPath string
	ln       net.Listener

	mu       sync.Mutex
	requests []daemon.SocketRequest
	// responder returns a response per request; nil means "OK, no data".
	responder func(daemon.SocketRequest) daemon.SocketResponse
}

func newMockDaemon(t *testing.T, responder func(daemon.SocketRequest) daemon.SocketResponse) *mockDaemon {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "daemon.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("mockDaemon: listen: %v", err)
	}
	m := &mockDaemon{sockPath: sockPath, ln: ln, responder: responder}
	go m.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})
	return m
}

func (m *mockDaemon) serve() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close() //nolint:errcheck // test cleanup
			var req daemon.SocketRequest
			if err := json.NewDecoder(c).Decode(&req); err != nil {
				return
			}
			m.mu.Lock()
			m.requests = append(m.requests, req)
			responder := m.responder
			m.mu.Unlock()
			resp := daemon.SocketResponse{OK: true}
			if responder != nil {
				resp = responder(req)
			}
			_ = json.NewEncoder(c).Encode(resp)
		}(conn)
	}
}

func (m *mockDaemon) history() []daemon.SocketRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]daemon.SocketRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

// sessionCSRF returns the CSRF token bound to the client's live session on
// srv. Tests use it to attach the token to POST forms so the CSRF gate
// (Phase 4) does not reject legitimate assertions.
func sessionCSRF(t *testing.T, srv *Server, client *http.Client, baseURL string) string {
	t.Helper()
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name != sessionCookieName {
			continue
		}
		info, ok := srv.sessions.Lookup(c.Value)
		if !ok {
			t.Fatalf("session cookie %s not found in store", c.Value)
		}
		return info.CSRF
	}
	t.Fatalf("no session cookie in jar for %s", baseURL)
	return ""
}

// authedPostForm wraps doPostForm to append the current session's CSRF
// token to form so Phase 4 POST handlers accept the request.
func authedPostForm(t *testing.T, srv *Server, client *http.Client, baseURL, path string, form url.Values) *http.Response {
	t.Helper()
	form.Set(csrfFormField, sessionCSRF(t, srv, client, baseURL))
	return doPostForm(t, client, baseURL+path, form)
}

// newAuthedTestServer builds a dashboard Server wired to the given daemon
// socket path, bootstraps an admin account, and returns an authed client
// (session cookie already stored in the jar) plus the base URL.
func newAuthedTestServer(t *testing.T, daemonSockPath string) (*Server, *http.Client, string, func()) {
	t.Helper()
	dir := t.TempDir()
	srv, err := New(Config{
		Addr:             "127.0.0.1:0",
		AuthDBPath:       filepath.Join(dir, "dashboard.db"),
		DaemonSocketPath: daemonSockPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const password = "correct-horse-battery-staple"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if err := srv.store.setAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatalf("setAdmin: %v", err)
	}

	ts := httptest.NewTLSServer(srv.Handler())
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Log the user in so the follow-up requests carry a valid session.
	loginForm := url.Values{"username": {"admin"}, "password": {password}}
	loginResp := doPostForm(t, client, ts.URL+"/login", loginForm)
	closeBody(t, loginResp)
	if loginResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: unexpected status %d", loginResp.StatusCode)
	}

	cleanup := func() {
		ts.Close()
		_ = srv.Close()
	}
	return srv, client, ts.URL, cleanup
}

func TestStatusPage_DaemonOffline(t *testing.T) {
	// No daemon socket configured on this server => graceful offline path.
	_, client, base, cleanup := newAuthedTestServer(t, "")
	defer cleanup()

	resp := doGet(t, client, base+"/dashboard")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "Daemon is offline") {
		t.Errorf("expected offline banner; body:\n%s", body)
	}
	if !strings.Contains(body, "Status") {
		t.Errorf("expected page title Status; body:\n%s", body)
	}
}

func TestStatusPage_LiveDaemon(t *testing.T) {
	statusPayload := daemon.StatusData{
		Uptime:     "3h2m",
		Armed:      true,
		ActiveBans: 5,
		Version:    "0.9.0",
	}
	listPayload := []daemon.BanEntry{
		{IP: "203.0.113.1", TTL: "5m", Strike: 1, Reason: "sshd"},
		{IP: "203.0.113.2", TTL: "1h", Strike: 2, Reason: "sshd"},
		{IP: "203.0.113.3", TTL: "permanent", Strike: 5, Reason: "wp-login"},
	}
	md := newMockDaemon(t, func(req daemon.SocketRequest) daemon.SocketResponse {
		switch req.Verb {
		case "status":
			raw, _ := json.Marshal(statusPayload)
			return daemon.SocketResponse{OK: true, Data: raw}
		case "list":
			raw, _ := json.Marshal(listPayload)
			return daemon.SocketResponse{OK: true, Data: raw}
		}
		return daemon.SocketResponse{OK: false, Error: "unknown verb"}
	})
	_, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := doGet(t, client, base+"/dashboard")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if strings.Contains(body, "Daemon is offline") {
		t.Errorf("expected no offline banner when daemon answers; body:\n%s", body)
	}
	// The status card should surface the version + uptime + active-ban count.
	for _, want := range []string{"3h2m", "0.9.0", "enforce"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body:\n%s", want, body)
		}
	}
	// The strike breakdown should list strike 1, 2 and permanent.
	for _, want := range []string{"strike 1", "strike 2", "permanent"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing strike bucket %q; body:\n%s", want, body)
		}
	}
}

func TestBansPage_LiveDaemon(t *testing.T) {
	listPayload := []daemon.BanEntry{
		{IP: "198.51.100.10", TTL: "5m", Strike: 1, Reason: "sshd", Country: "BR", ASN: "AS1234"},
	}
	md := newMockDaemon(t, func(req daemon.SocketRequest) daemon.SocketResponse {
		if req.Verb == "list" {
			raw, _ := json.Marshal(listPayload)
			return daemon.SocketResponse{OK: true, Data: raw}
		}
		return daemon.SocketResponse{OK: true}
	})
	_, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := doGet(t, client, base+"/dashboard/bans")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	for _, want := range []string{"198.51.100.10", "BR", "AS1234", "sshd", "Unban"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body:\n%s", want, body)
		}
	}
}

func TestBansPage_EmptyDaemon(t *testing.T) {
	md := newMockDaemon(t, func(req daemon.SocketRequest) daemon.SocketResponse {
		return daemon.SocketResponse{OK: true, Data: json.RawMessage("[]")}
	})
	_, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := doGet(t, client, base+"/dashboard/bans")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "No active bans") {
		t.Errorf("expected empty-state message; body:\n%s", body)
	}
}

func TestAllowlistPage_LiveDaemon(t *testing.T) {
	entries := []daemon.AllowEntry{
		{Prefix: "192.0.2.0/24", Expires: "never", Reason: "office egress"},
	}
	md := newMockDaemon(t, func(req daemon.SocketRequest) daemon.SocketResponse {
		if req.Verb == "list_allow" {
			raw, _ := json.Marshal(entries)
			return daemon.SocketResponse{OK: true, Data: raw}
		}
		return daemon.SocketResponse{OK: true}
	})
	_, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := doGet(t, client, base+"/dashboard/allowlist")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	for _, want := range []string{"192.0.2.0/24", "never", "office egress"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body:\n%s", want, body)
		}
	}
}

func TestPages_RequireAuth(t *testing.T) {
	// Build a bare server (no login) via newTestServer, which produces an
	// unauthed client. Any of the Phase 2 pages must 303 to /login.
	_, client, base, cleanup := newTestServer(t, "irrelevant")
	defer cleanup()

	for _, path := range []string{
		"/dashboard",
		"/dashboard/bans",
		"/dashboard/allowlist",
	} {
		resp := doGet(t, client, base+path)
		closeBody(t, resp)
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("GET %s status = %d, want 303", path, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "/login" {
			t.Errorf("GET %s Location = %q, want /login", path, loc)
		}
	}
}

func TestBanPost_ValidatesIP(t *testing.T) {
	md := newMockDaemon(t, nil)
	srv, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	cases := []struct {
		name     string
		form     url.Values
		wantCode string
		wantHit  bool // whether the daemon should see a ban request
	}{
		{"empty", url.Values{"ip": {""}}, "missing-ip", false},
		{"bogus", url.Values{"ip": {"not-an-ip"}}, "invalid-ip", false},
		{"hostname", url.Values{"ip": {"example.com"}}, "invalid-ip", false},
		{"valid v4", url.Values{"ip": {"203.0.113.7"}, "reason": {"sshd"}}, "ban-queued", true},
		{"valid v4 cidr", url.Values{"ip": {"203.0.113.0/24"}}, "ban-queued", true},
		{"valid v6", url.Values{"ip": {"2001:db8::1"}}, "ban-queued", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(md.history())
			resp := authedPostForm(t, srv, client, base, "/dashboard/ban", tc.form)
			closeBody(t, resp)
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", resp.StatusCode)
			}
			loc := resp.Header.Get("Location")
			if !strings.HasPrefix(loc, "/dashboard/bans") {
				t.Errorf("Location = %q, want /dashboard/bans...", loc)
			}
			if !strings.Contains(loc, tc.wantCode) {
				t.Errorf("Location = %q, want to contain %q", loc, tc.wantCode)
			}
			after := len(md.history())
			hit := after > before
			if hit != tc.wantHit {
				t.Errorf("daemon hit = %v, want %v (history: %+v)", hit, tc.wantHit, md.history()[before:])
			}
			if tc.wantHit {
				req := md.history()[after-1]
				if req.Verb != "ban" {
					t.Errorf("verb = %q, want ban", req.Verb)
				}
				if req.IP == "" {
					t.Errorf("daemon received empty IP; req = %+v", req)
				}
			}
		})
	}
}

func TestUnbanPost_ValidatesAndDispatches(t *testing.T) {
	md := newMockDaemon(t, nil)
	srv, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	// invalid IP → no daemon hit
	resp := authedPostForm(t, srv, client, base, "/dashboard/unban", url.Values{"ip": {"garbage"}})
	closeBody(t, resp)
	if !strings.Contains(resp.Header.Get("Location"), "invalid-ip") {
		t.Errorf("Location = %q, want invalid-ip", resp.Header.Get("Location"))
	}
	if len(md.history()) != 0 {
		t.Errorf("daemon should not have been called; history: %+v", md.history())
	}

	// valid IP → daemon receives unban verb
	resp2 := authedPostForm(t, srv, client, base, "/dashboard/unban", url.Values{"ip": {"203.0.113.9"}})
	closeBody(t, resp2)
	if !strings.Contains(resp2.Header.Get("Location"), "unban-queued") {
		t.Errorf("Location = %q, want unban-queued", resp2.Header.Get("Location"))
	}
	hist := md.history()
	if len(hist) != 1 || hist[0].Verb != "unban" {
		t.Fatalf("expected 1 unban call, got %+v", hist)
	}
}

func TestAllowPost_ValidatesAndDispatches(t *testing.T) {
	md := newMockDaemon(t, nil)
	srv, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	// invalid CIDR → no daemon hit
	resp := authedPostForm(t, srv, client, base, "/dashboard/allow", url.Values{"ip": {"999.999.999.999"}})
	closeBody(t, resp)
	if !strings.Contains(resp.Header.Get("Location"), "invalid-ip") {
		t.Errorf("Location = %q, want invalid-ip", resp.Header.Get("Location"))
	}
	if len(md.history()) != 0 {
		t.Errorf("daemon should not have been called; history: %+v", md.history())
	}

	// valid CIDR → daemon receives allow verb + tagged reason ("dashboard:admin: office").
	resp2 := authedPostForm(t, srv, client, base, "/dashboard/allow", url.Values{
		"ip":     {"192.0.2.0/24"},
		"reason": {"office"},
	})
	closeBody(t, resp2)
	if !strings.Contains(resp2.Header.Get("Location"), "allow-added") {
		t.Errorf("Location = %q, want allow-added", resp2.Header.Get("Location"))
	}
	hist := md.history()
	if len(hist) != 1 || hist[0].Verb != "allow" || hist[0].Reason != "dashboard:admin: office" {
		t.Fatalf("expected 1 allow call with reason=dashboard:admin: office, got %+v", hist)
	}
}

func TestBanPost_DaemonOffline(t *testing.T) {
	// Empty daemon socket path → the RPC layer returns
	// daemon.ErrDaemonUnreachable and the handler must render the
	// daemon-offline flash on the redirect target.
	srv, client, base, cleanup := newAuthedTestServer(t, "")
	defer cleanup()

	resp := authedPostForm(t, srv, client, base, "/dashboard/ban", url.Values{"ip": {"203.0.113.7"}})
	closeBody(t, resp)
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "daemon-offline") {
		t.Errorf("Location = %q, want daemon-offline", loc)
	}
}

func TestCanonicalPrefix(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"203.0.113.7", "203.0.113.7/32", true},
		{"203.0.113.0/24", "203.0.113.0/24", true},
		{"203.0.113.5/24", "203.0.113.0/24", true}, // masked
		{"2001:db8::1", "2001:db8::1/128", true},
		{"", "", false},
		{"example.com", "", false},
		{"999.999.999.999", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := canonicalPrefix(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (got=%q)", ok, tc.ok, got)
			}
			if ok && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
