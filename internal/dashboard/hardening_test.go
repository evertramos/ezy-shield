package dashboard

// Tests for the Phase 4 audit launch-blockers: operator reason validation
// before the daemon RPC (issue #85) and logout behind the same auth + CSRF
// gates as every other mutation (issue #86).

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestValidReason(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		want   bool
	}{
		{"empty accepted", "", true},
		{"plain text accepted", "manual ban after abuse report", true},
		{"tab accepted", "col1\tcol2", true},
		{"exactly 500 runes accepted", strings.Repeat("a", 500), true},
		{"501 runes rejected", strings.Repeat("a", 501), false},
		{"500 multibyte runes accepted (cap is runes, not bytes)", strings.Repeat("é", 500), true},
		{"newline rejected", "line1\nline2", false},
		{"carriage return rejected", "spoof\rlog", false},
		{"NUL rejected", "a\x00b", false},
		{"ANSI escape rejected", "\x1b[31mred\x1b[0m", false},
		{"DEL rejected", "a\x7fb", false},
		{"invalid UTF-8 rejected", "bad\xffbytes", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validReason(tc.reason); got != tc.want {
				t.Errorf("validReason(%q) = %v, want %v", tc.reason, got, tc.want)
			}
		})
	}
}

// TestBanPost_BadReasonRejected proves an out-of-policy reason never reaches
// the daemon and surfaces the bad-reason flash code to the operator.
func TestBanPost_BadReasonRejected(t *testing.T) {
	md := newMockDaemon(t, nil)
	srv, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := authedPostForm(t, srv, client, base, "/dashboard/ban", url.Values{
		"ip":     {"203.0.113.7"},
		"reason": {strings.Repeat("a", 501)},
	})
	closeBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 redirect with flash", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "err=bad-reason") {
		t.Errorf("Location = %q, want err=bad-reason flash", loc)
	}
	if len(md.history()) != 0 {
		t.Errorf("daemon must not be called with an invalid reason; got %+v", md.history())
	}
}

// TestBanPost_ReasonAtCapAccepted guards the boundary: exactly 500 runes is
// still a valid reason and the action reaches the daemon.
func TestBanPost_ReasonAtCapAccepted(t *testing.T) {
	md := newMockDaemon(t, nil)
	srv, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := authedPostForm(t, srv, client, base, "/dashboard/ban", url.Values{
		"ip":     {"203.0.113.7"},
		"reason": {strings.Repeat("a", 500)},
	})
	closeBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if len(md.history()) != 1 {
		t.Errorf("expected one daemon call for a valid reason, got %+v", md.history())
	}
}

// TestLogout_MissingCSRFRejected proves logout obeys the same CSRF invariant
// as every other POST: no token → 403 and the session survives.
func TestLogout_MissingCSRFRejected(t *testing.T) {
	md := newMockDaemon(t, nil)
	_, client, base, cleanup := newAuthedTestServer(t, md.sockPath)
	defer cleanup()

	resp := doPostForm(t, client, base+"/logout", url.Values{})
	closeBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without CSRF: status = %d, want 403", resp.StatusCode)
	}

	// The session must still be alive: an authed page renders normally.
	page := doGet(t, client, base+"/dashboard")
	defer closeBody(t, page)
	if page.StatusCode != http.StatusOK {
		t.Errorf("session should survive a forged logout; GET /dashboard = %d, want 200", page.StatusCode)
	}
}

// TestLogout_UnauthenticatedRedirected proves requireAuth fronts logout: a
// caller with no session is sent to /login instead of reaching the handler.
func TestLogout_UnauthenticatedRedirected(t *testing.T) {
	_, client, base, cleanup := newTestServer(t, "correct-horse-battery-staple")
	defer cleanup()

	resp := doPostForm(t, client, base+"/logout", url.Values{})
	closeBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unauthenticated logout: status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}
