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
	"time"
)

// newTestServer builds a Server with a per-test SQLite file. It bootstraps
// the "admin" account with a caller-supplied password and returns the
// ready-to-use server plus the http.Client + base URL wired via httptest.
//
// httptest.NewTLSServer is used so that Secure cookies set by the login
// handler round-trip through the cookie jar; the production dashboard runs
// over plain HTTP on loopback (browsers treat localhost as a secure
// context), but tests need TLS to exercise the Secure flag.
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
	cleanup := func() {
		ts.Close()
		if err := srv.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	}
	return srv, client, ts.URL, cleanup
}

func doGet(t *testing.T, client *http.Client, target string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", target, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	return resp
}

func doPostForm(t *testing.T, client *http.Client, target string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build POST %s: %v", target, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	return resp
}

func closeBody(t *testing.T, resp *http.Response) {
	t.Helper()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Logf("drain body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Logf("close body: %v", err)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Logf("close body: %v", err)
	}
	return string(b)
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

// TestRun_BoundAddrFrozen proves that Run binds to the address frozen on
// boundAddr at construction time, not to cfg.Addr — so an errant future
// write to cfg.Addr (there is none in this package today) cannot change
// where the dashboard listens.
func TestRun_BoundAddrFrozen(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(Config{
		Addr:       "127.0.0.1:0",
		AuthDBPath: filepath.Join(dir, "dashboard.db"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		if err := srv.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	}()

	want := srv.boundAddr
	if want == "" {
		t.Fatal("boundAddr was not populated by New")
	}

	// Simulate an errant future write to cfg.Addr after construction.
	srv.cfg.Addr = "0.0.0.0:9090"

	if srv.boundAddr != want {
		t.Fatalf("boundAddr changed from %q to %q after mutating cfg.Addr", want, srv.boundAddr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- srv.Run(ctx) }()

	// Give Run a moment to either bind successfully or fail; a non-loopback
	// bind (from the mutated cfg.Addr) would fail fast with a loopback
	// error, so a short wait is enough to distinguish the two outcomes.
	select {
	case err := <-runErrCh:
		t.Fatalf("Run returned early (should have bound to frozen boundAddr %q and kept serving): %v", want, err)
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	if err := <-runErrCh; err != nil {
		t.Fatalf("Run: unexpected error after cancel: %v", err)
	}

	if srv.boundAddr != want {
		t.Fatalf("boundAddr changed from %q to %q over the lifetime of Run", want, srv.boundAddr)
	}
}

func TestIndex_RequiresAuth(t *testing.T) {
	_, client, base, cleanup := newTestServer(t, "correct-horse-battery-staple")
	defer cleanup()

	resp := doGet(t, client, base+"/")
	defer closeBody(t, resp)
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

	form := url.Values{"username": {"admin"}, "password": {"wrong"}}
	resp := doPostForm(t, client, base+"/login", form)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(body, "Invalid credentials") {
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

	form := url.Values{"username": {"ghost"}, "password": {"irrelevant"}}
	resp := doPostForm(t, client, base+"/login", form)
	defer closeBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestLogin_ConstantTimeAgainstEnumeration asserts that the unknown-username
// path actually runs PBKDF2 against the decoy hash (CWE-208 regression). A
// naive implementation short-circuits when the admin row is missing and
// returns in ~1 ms, which distinguishes real from unknown usernames by
// wall-clock time. Because PBKDF2 with 600 000 iterations of SHA-256 takes
// >100 ms on every CI target we run against, the threshold below survives
// slow runners while still catching a regression that skipped the KDF work.
func TestLogin_ConstantTimeAgainstEnumeration(t *testing.T) {
	_, client, base, cleanup := newTestServer(t, "correct-horse-battery-staple")
	defer cleanup()

	measure := func(username string) time.Duration {
		form := url.Values{"username": {username}, "password": {"irrelevant"}}
		start := time.Now()
		resp := doPostForm(t, client, base+"/login", form)
		closeBody(t, resp)
		return time.Since(start)
	}
	// Warm up: the very first PBKDF2 call after process start can be
	// slower on some runners; discard the reading.
	_ = measure("warmup")

	unknownDur := measure("ghost")
	knownDur := measure("admin")

	const minPBKDF2Time = 100 * time.Millisecond
	if unknownDur < minPBKDF2Time {
		t.Errorf("unknown-user path returned in %s (< %s); PBKDF2 was probably skipped, enabling username enumeration (CWE-208)",
			unknownDur, minPBKDF2Time)
	}
	if knownDur < minPBKDF2Time {
		t.Errorf("known-user path returned in %s (< %s); PBKDF2 iterations may have been lowered",
			knownDur, minPBKDF2Time)
	}
}

func TestLogin_SuccessGrantsAccess(t *testing.T) {
	_, client, base, cleanup := newTestServer(t, "correct-horse-battery-staple")
	defer cleanup()

	form := url.Values{"username": {"admin"}, "password": {"correct-horse-battery-staple"}}
	resp := doPostForm(t, client, base+"/login", form)
	closeBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}

	// The cookie jar picked up the session cookie on the login response.
	// GET / now redirects the authed session to /dashboard (Phase 2 root
	// redirect), so the follow-up asserts one hop through the status page.
	resp2 := doGet(t, client, base+"/")
	closeBody(t, resp2)
	if resp2.StatusCode != http.StatusSeeOther {
		t.Fatalf("authenticated GET / status = %d, want 303", resp2.StatusCode)
	}
	if loc := resp2.Header.Get("Location"); loc != "/dashboard" {
		t.Errorf("Location = %q, want /dashboard", loc)
	}

	resp3 := doGet(t, client, base+"/dashboard")
	body := readBody(t, resp3)
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("authenticated GET /dashboard status = %d, want 200", resp3.StatusCode)
	}
	// No daemon socket is configured on the test server, so the status
	// page renders with the graceful "daemon offline" banner.
	if !strings.Contains(body, "Daemon is offline") {
		t.Errorf("body should render status page with offline banner, got: %s", body)
	}
}

func TestLogout_ClearsSession(t *testing.T) {
	srv, client, base, cleanup := newTestServer(t, "correct-horse-battery-staple")
	defer cleanup()

	form := url.Values{"username": {"admin"}, "password": {"correct-horse-battery-staple"}}
	loginResp := doPostForm(t, client, base+"/login", form)
	closeBody(t, loginResp)

	// Logout is auth- and CSRF-gated like every other POST (issue #86), so
	// the real browser flow carries the session's token.
	logoutResp := authedPostForm(t, srv, client, base, "/logout", url.Values{})
	closeBody(t, logoutResp)

	resp := doGet(t, client, base+"/")
	defer closeBody(t, resp)
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
	defer func() {
		if err := srv.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	}()

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
