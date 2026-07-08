package dashboard

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// newTestServer builds a Server with a per-test SQLite file. It bootstraps
// the "admin" account with a caller-supplied password and returns the ready-
// to-use server plus the http.Client + base URL wired via httptest.
func newTestServer(t *testing.T, adminPassword string) (*Server, *http.Client, string, func()) {
	t.Helper()
	dir := t.TempDir()
	srv, err := New(Config{
		Addr:       "127.0.0.1:0",
		AuthDBPath: filepath.Join(dir, "dashboard.db"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hash, err := hashPassword(adminPassword)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if err := srv.store.SetAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := ts.Client()
	client.Jar = jar
	// Do not follow redirects — tests inspect each hop.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	cleanup := func() {
		ts.Close()
		if err := srv.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	}
	return srv, client, ts.URL, cleanup
}

func TestCheckLoopback(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"ipv4 loopback", "127.0.0.1:9090", false},
		{"ipv4 loopback alt", "127.0.0.53:9090", false},
		{"ipv6 loopback", "[::1]:9090", false},
		{"localhost literal", "localhost:9090", false},
		{"wildcard v4", "0.0.0.0:9090", true},
		{"wildcard v6", "[::]:9090", true},
		{"public v4", "192.0.2.1:9090", true},
		{"empty host", ":9090", true},
		{"bad host", "not-an-ip:9090", true},
		{"missing port", "127.0.0.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkLoopback(tc.addr)
			if tc.wantErr && err == nil {
				t.Fatalf("addr %q: expected error, got nil", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("addr %q: unexpected error: %v", tc.addr, err)
			}
		})
	}
}

func TestNew_RefusesNonLoopback(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Config{
		Addr:       "0.0.0.0:9090",
		AuthDBPath: filepath.Join(dir, "dashboard.db"),
	})
	if err == nil {
		t.Fatal("expected New to refuse 0.0.0.0 bind, got nil error")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("error message should mention loopback, got: %v", err)
	}
}

func TestRun_RefusesNonLoopback(t *testing.T) {
	dir := t.TempDir()
	// Bypass New's guard by constructing the Server directly, then mutating
	// cfg.Addr. This proves Run has its own defence-in-depth check.
	srv, err := New(Config{
		Addr:       "127.0.0.1:0",
		AuthDBPath: filepath.Join(dir, "dashboard.db"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close() //nolint:errcheck // test cleanup
	srv.cfg.Addr = "0.0.0.0:9090"
	err = srv.Run(context.Background())
	if err == nil {
		t.Fatal("expected Run to refuse 0.0.0.0, got nil error")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("error message should mention loopback, got: %v", err)
	}
}

func TestIndex_RequiresAuth(t *testing.T) {
	_, client, base, cleanup := newTestServer(t, "correct-horse-battery-staple")
	defer cleanup()

	resp, err := client.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	_, client, base, cleanup := newTestServer(t, "correct-horse-battery-staple")
	defer cleanup()

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "wrong")
	resp, err := client.PostForm(base+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Invalid credentials") {
		t.Errorf("body should contain 'Invalid credentials', got: %s", body)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Errorf("wrong password should NOT set session cookie; got %q", c.Value)
		}
	}
}

func TestLogin_UnknownUser(t *testing.T) {
	// Enumeration guard: unknown username must produce the same 401 +
	// "Invalid credentials" response as a wrong password.
	_, client, base, cleanup := newTestServer(t, "correct-horse-battery-staple")
	defer cleanup()

	form := url.Values{}
	form.Set("username", "ghost")
	form.Set("password", "irrelevant")
	resp, err := client.PostForm(base+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestLogin_SuccessGrantsAccess(t *testing.T) {
	_, client, base, cleanup := newTestServer(t, "correct-horse-battery-staple")
	defer cleanup()

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "correct-horse-battery-staple")
	resp, err := client.PostForm(base+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	// Read + close the redirect body so the connection is reusable.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}

	// The httptest cookie jar picked up the session cookie on the previous
	// response; the next request should reach the index without redirect.
	resp2, err := client.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck // test cleanup
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("authenticated GET / status = %d, want 200", resp2.StatusCode)
	}
	body, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(body), "Dashboard scaffold") {
		t.Errorf("body should render index, got: %s", body)
	}
}

func TestLogout_ClearsSession(t *testing.T) {
	_, client, base, cleanup := newTestServer(t, "correct-horse-battery-staple")
	defer cleanup()

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "correct-horse-battery-staple")
	loginResp, err := client.PostForm(base+"/login", form)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := io.Copy(io.Discard, loginResp.Body); err != nil {
		t.Fatalf("drain: %v", err)
	}
	loginResp.Body.Close() //nolint:errcheck // test cleanup

	logoutResp, err := client.PostForm(base+"/logout", nil)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := io.Copy(io.Discard, logoutResp.Body); err != nil {
		t.Fatalf("drain: %v", err)
	}
	logoutResp.Body.Close() //nolint:errcheck // test cleanup

	// After logout, / must redirect to /login again.
	resp, err := client.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("post-logout GET / status = %d, want 303", resp.StatusCode)
	}
}

func TestEnsureAdmin_IdempotentBootstrap(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(Config{
		Addr:       "127.0.0.1:0",
		AuthDBPath: filepath.Join(dir, "dashboard.db"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close() //nolint:errcheck // test cleanup

	pw, created, err := srv.EnsureAdmin(context.Background())
	if err != nil {
		t.Fatalf("first EnsureAdmin: %v", err)
	}
	if !created {
		t.Fatal("first call should create admin")
	}
	if len(pw) < 20 {
		t.Errorf("generated password too short: %q (len=%d)", pw, len(pw))
	}

	// Second call must NOT re-generate a password or overwrite the hash.
	pw2, created2, err := srv.EnsureAdmin(context.Background())
	if err != nil {
		t.Fatalf("second EnsureAdmin: %v", err)
	}
	if created2 {
		t.Fatal("second call should be a no-op")
	}
	if pw2 != "" {
		t.Errorf("second call should return empty password, got %q", pw2)
	}
}
