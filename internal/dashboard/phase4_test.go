package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// TestCSRF_MissingTokenRejected proves the CSRF gate blocks a POST that
// carries no token even when the session cookie is valid — the exact
// scenario a cross-site-forged form would trigger.
func TestCSRF_MissingTokenRejected(t *testing.T) {
	md := newMockDaemon(t, nil)
	_, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	// Deliberately do NOT go through authedPostForm — no csrf_token.
	resp := doPostForm(t, client, base+"/dashboard/ban", url.Values{"ip": {"203.0.113.7"}})
	closeBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if len(md.history()) != 0 {
		t.Errorf("daemon should not be called on CSRF failure; got %+v", md.history())
	}
}

func TestCSRF_WrongTokenRejected(t *testing.T) {
	md := newMockDaemon(t, nil)
	_, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := doPostForm(t, client, base+"/dashboard/ban", url.Values{
		"ip":         {"203.0.113.7"},
		"csrf_token": {"deadbeef-not-the-real-token"},
	})
	closeBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if len(md.history()) != 0 {
		t.Errorf("daemon should not be called with wrong CSRF; got %+v", md.history())
	}
}

func TestCSRF_ValidTokenAccepted(t *testing.T) {
	md := newMockDaemon(t, nil)
	srv, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := authedPostForm(t, srv, client, base, "/dashboard/ban", url.Values{"ip": {"203.0.113.7"}})
	closeBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 with valid CSRF", resp.StatusCode)
	}
	if len(md.history()) != 1 {
		t.Errorf("expected one daemon hit, got %+v", md.history())
	}
}

// TestCSRF_HiddenInputEmbedded confirms the hidden csrf_token input is
// actually rendered on the bans form. Guards against a future template
// refactor silently dropping the token.
func TestCSRF_HiddenInputEmbedded(t *testing.T) {
	md := newMockDaemon(t, func(req daemon.SocketRequest) daemon.SocketResponse {
		return daemon.SocketResponse{OK: true, Data: json.RawMessage("[]")}
	})
	srv, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := doGet(t, client, base+"/dashboard/bans")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	csrf := sessionCSRF(t, srv, client, base)
	want := `name="csrf_token" value="` + csrf + `"`
	if !strings.Contains(body, want) {
		t.Errorf("ban page missing csrf hidden input\nwant substring: %s\nbody:\n%s", want, body)
	}
}

func TestLoginThrottle_LocksOutAfter5Failures(t *testing.T) {
	th := newLoginThrottle()
	fakeNow := time.Unix(1_000_000, 0)
	th.nowClock = func() time.Time { return fakeNow }

	for i := 0; i < 5; i++ {
		if !th.Allow("admin") {
			t.Fatalf("Allow returned false at attempt %d; want true", i+1)
		}
		th.RecordFailure("admin")
	}
	if th.Allow("admin") {
		t.Fatal("6th attempt should be locked out")
	}

	// Rolling the clock past the lockout unblocks the account.
	fakeNow = fakeNow.Add(2 * time.Minute)
	if !th.Allow("admin") {
		t.Fatal("Allow should be true after lockout window expires")
	}
}

func TestLoginThrottle_ClearOnSuccess(t *testing.T) {
	th := newLoginThrottle()
	fakeNow := time.Unix(2_000_000, 0)
	th.nowClock = func() time.Time { return fakeNow }
	th.RecordFailure("admin")
	th.RecordFailure("admin")
	th.Clear("admin")

	for i := 0; i < 4; i++ {
		if !th.Allow("admin") {
			t.Fatalf("Allow returned false at attempt %d after Clear", i+1)
		}
		th.RecordFailure("admin")
	}
	if !th.Allow("admin") {
		t.Fatal("account should still be allowed at 4 fresh failures")
	}
}

func TestLoginRateLimit_EndToEnd(t *testing.T) {
	md := newMockDaemon(t, nil)
	_, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	// The setup already logged 'admin' in successfully → the throttle is
	// clean. Now send 5 bogus passwords.
	for i := 0; i < 5; i++ {
		resp := doPostForm(t, client, base+"/login", url.Values{
			"username": {"admin"},
			"password": {"wrong"},
		})
		closeBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i+1, resp.StatusCode)
		}
	}
	// 6th attempt is throttled.
	resp := doPostForm(t, client, base+"/login", url.Values{
		"username": {"admin"},
		"password": {"wrong"},
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("6th status = %d, want 429\nbody: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Too many failed attempts") {
		t.Errorf("expected lockout banner in body, got: %s", body)
	}
}

func TestSessionCap_EvictsOldest(t *testing.T) {
	s := newSessionStore(time.Hour)
	first, _, err := s.Create("admin")
	if err != nil {
		t.Fatalf("Create 1: %v", err)
	}
	second, _, err := s.Create("admin")
	if err != nil {
		t.Fatalf("Create 2: %v", err)
	}
	third, _, err := s.Create("admin")
	if err != nil {
		t.Fatalf("Create 3: %v", err)
	}

	for _, tok := range []string{first, second, third} {
		if _, ok := s.Lookup(tok); !ok {
			t.Errorf("session %s should be live", tok)
		}
	}
	if got := s.userLen("admin"); got != 3 {
		t.Fatalf("userLen = %d, want 3", got)
	}

	fourth, _, err := s.Create("admin")
	if err != nil {
		t.Fatalf("Create 4: %v", err)
	}
	if _, ok := s.Lookup(first); ok {
		t.Error("oldest session should have been evicted")
	}
	for _, tok := range []string{second, third, fourth} {
		if _, ok := s.Lookup(tok); !ok {
			t.Errorf("session %s should still be live", tok)
		}
	}
	if got := s.userLen("admin"); got != 3 {
		t.Fatalf("userLen after cap = %d, want 3", got)
	}
}

func TestSessionCap_ScopedPerUser(t *testing.T) {
	s := newSessionStore(time.Hour)
	aliceTok, _, err := s.Create("alice")
	if err != nil {
		t.Fatalf("alice create: %v", err)
	}
	for i := 0; i < maxSessionsPerUser; i++ {
		if _, _, err := s.Create("bob"); err != nil {
			t.Fatalf("bob create %d: %v", i, err)
		}
	}
	if _, _, err := s.Create("bob"); err != nil {
		t.Fatalf("bob overflow: %v", err)
	}
	if _, ok := s.Lookup(aliceTok); !ok {
		t.Fatal("alice's session should survive bob's overflow")
	}
	if got := s.userLen("bob"); got != maxSessionsPerUser {
		t.Errorf("bob userLen = %d, want %d", got, maxSessionsPerUser)
	}
}

func TestTimelinePage_RendersPerIPLadder(t *testing.T) {
	bans := []daemon.BanEntry{
		{IP: "203.0.113.7", Strike: 2, TTL: "1h", Country: "BR", ASN: "AS12345"},
	}
	events := []daemon.EventEntry{
		{ID: 20, RecordedAt: "2026-07-08T02:15:00Z", Op: "ban", IP: "203.0.113.7", Strike: 2, Reason: "sshd"},
		{ID: 10, RecordedAt: "2026-07-08T02:00:00Z", Op: "ban", IP: "203.0.113.7", Strike: 1, Reason: "sshd"},
	}
	md := newMockDaemon(t, func(req daemon.SocketRequest) daemon.SocketResponse {
		switch req.Verb {
		case "list":
			raw, _ := json.Marshal(bans)
			return daemon.SocketResponse{OK: true, Data: raw}
		case "events":
			raw, _ := json.Marshal(events)
			return daemon.SocketResponse{OK: true, Data: raw}
		}
		return daemon.SocketResponse{OK: true}
	})
	_, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := doGet(t, client, base+"/dashboard/timeline")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	for _, want := range []string{"203.0.113.7", "BR", "AS12345", "Current strike 2"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "reached") {
		t.Errorf("expected at least one reached ladder step in body:\n%s", body)
	}
}

func TestTimelinePage_DaemonOffline(t *testing.T) {
	_, client, base, cleanup := newAuthedTestServer(t, "")
	defer cleanup()

	resp := doGet(t, client, base+"/dashboard/timeline")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "Daemon is offline") {
		t.Errorf("timeline should render the offline banner; body:\n%s", body)
	}
}

func TestBuildTimeline_MergesAuditAndActive(t *testing.T) {
	bans := []daemon.BanEntry{
		{IP: "203.0.113.1", Strike: 3, TTL: "24h"},
	}
	events := []daemon.EventEntry{
		{ID: 5, RecordedAt: "t3", Op: "ban", IP: "203.0.113.1", Strike: 3, Reason: "escalation"},
		{ID: 3, RecordedAt: "t1", Op: "ban", IP: "203.0.113.1", Strike: 1},
		{ID: 4, RecordedAt: "t2", Op: "ban", IP: "203.0.113.1", Strike: 2},
	}
	tl := buildTimeline(bans, events)
	if len(tl) != 1 {
		t.Fatalf("timeline entries = %d, want 1", len(tl))
	}
	e := tl[0]
	if e.CurrentTier != 3 {
		t.Errorf("CurrentTier = %d, want 3", e.CurrentTier)
	}
	if len(e.Steps) != 5 {
		t.Fatalf("Steps len = %d, want 5", len(e.Steps))
	}
	for i, step := range e.Steps {
		wantReached := step.Strike <= 3
		if step.Reached != wantReached {
			t.Errorf("step %d reached = %v, want %v", i, step.Reached, wantReached)
		}
	}
	if e.Steps[0].RecordedAt != "t1" || e.Steps[2].RecordedAt != "t3" {
		t.Errorf("ladder timestamps wrong: %+v", e.Steps)
	}
}

func TestDashboardActionReason(t *testing.T) {
	if got := dashboardActionReason(""); got != "dashboard:admin" {
		t.Errorf("empty case = %q, want dashboard:admin", got)
	}
	if got := dashboardActionReason("office egress"); got != "dashboard:admin: office egress" {
		t.Errorf("with reason = %q, want dashboard:admin: office egress", got)
	}
}

// TestRequireCSRF_MissingSessionReturnsForbidden checks the
// programmer-error branch: if requireCSRF is called without requireAuth
// having attached a session, the response is 403 rather than a 500 or a
// silent success.
func TestRequireCSRF_MissingSessionReturnsForbidden(t *testing.T) {
	srv, _, _, cleanup := newAuthedTestServer(t, "")
	defer cleanup()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://example/dashboard/ban", strings.NewReader(""))
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	rec := &statusRecorder{header: make(http.Header)}
	if srv.requireCSRF(rec, req) {
		t.Fatal("requireCSRF should return false when session is absent")
	}
	if rec.status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.status)
	}
}

// statusRecorder is a tiny http.ResponseWriter capturing status code.
type statusRecorder struct {
	status int
	header http.Header
}

func (r *statusRecorder) Header() http.Header         { return r.header }
func (r *statusRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *statusRecorder) WriteHeader(status int)      { r.status = status }
