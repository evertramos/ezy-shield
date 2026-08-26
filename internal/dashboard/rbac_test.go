// SPDX-License-Identifier: AGPL-3.0-only

package dashboard

// RBAC tests (issue #204): permission table + deny-by-default, the
// role × endpoint matrix, constant-time token auth, implicit auth-DB
// admin compatibility, live reload semantics, 403 auditing, and CSRF
// still gating allowed mutations.

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// rbacTestUsers is the standard three-role fixture. Tokens are test-only.
func rbacTestUsers() []AuthUser {
	return []AuthUser{
		{Name: "vera", Role: "viewer", Token: "viewer-token-0123456789abcdef0123456789abcdef"},
		{Name: "omar", Role: "operator", Token: "operator-token-0123456789abcdef0123456789abcd"},
		{Name: "ada", Role: "admin", Token: "admin-token-0123456789abcdef0123456789abcdefab"},
	}
}

func newRBACTestServer(t *testing.T) (*Server, *http.Client, string, func()) {
	t.Helper()
	srv, client, base, cleanup := newTestServer(t, "db-admin-password-1234")
	srv.ReloadUsers(rbacTestUsers())
	return srv, client, base, cleanup
}

// loginAs performs a form login with a config user's name + token.
func loginAs(t *testing.T, client *http.Client, base, name, token string) {
	t.Helper()
	resp := doPostForm(t, client, base+"/login", url.Values{
		"username": {name},
		"password": {token},
	})
	closeBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login as %s: status %d, want 303", name, resp.StatusCode)
	}
}

func TestRequiredRole_DenyByDefault(t *testing.T) {
	t.Parallel()
	if requiredRole("ban") != RoleOperator || requiredRole("allow") != RoleAdmin || requiredRole("view") != RoleViewer {
		t.Errorf("permission table drifted")
	}
	// The critical invariant: anything unclassified requires admin.
	for _, unknown := range []string{"future_endpoint", "policy_rewrite", ""} {
		if requiredRole(unknown) != RoleAdmin {
			t.Errorf("unknown action %q must require admin (deny by default)", unknown)
		}
	}
}

func TestUserSet_ConstantTimeAuthenticate(t *testing.T) {
	t.Parallel()
	set := newUserSet(rbacTestUsers())

	if u, ok := set.authenticate("omar", "operator-token-0123456789abcdef0123456789abcd"); !ok || u.role != RoleOperator {
		t.Errorf("valid credentials rejected: %v %v", u, ok)
	}
	if _, ok := set.authenticate("omar", "wrong-token"); ok {
		t.Errorf("wrong token accepted")
	}
	if _, ok := set.authenticate("nobody", "operator-token-0123456789abcdef0123456789abcd"); ok {
		t.Errorf("valid token under the wrong name accepted")
	}
	if _, ok := newUserSet(nil).authenticate("omar", "anything"); ok {
		t.Errorf("empty set accepted a login")
	}
	// Constant-time note (AC): authenticate compares fixed-size PBKDF2
	// digests via subtle.ConstantTimeCompare for EVERY stored user with no
	// early exit; see rbac.go — this test pins behavior, the code review
	// note pins the mechanism.
}

// TestRBAC_RoleEndpointMatrix drives the role × endpoint matrix through
// the real HTTP stack: viewers cannot POST ban, operators cannot mutate
// the allowlist, admins can do both. 403 means RBAC refused; anything
// else means the request reached the handler (daemon-offline flashes
// included — the daemon socket is not wired in this harness).
func TestRBAC_RoleEndpointMatrix(t *testing.T) {
	srv, client, base, cleanup := newRBACTestServer(t)
	defer cleanup()

	users := rbacTestUsers()
	cases := []struct {
		user      AuthUser
		path      string
		wantDeny  bool
		wantAudit string // action recorded on deny
	}{
		{users[0], "/dashboard/ban", true, "ban"},
		{users[0], "/dashboard/unban", true, "unban"},
		{users[0], "/dashboard/allow", true, "allow"},
		{users[1], "/dashboard/ban", false, ""},
		{users[1], "/dashboard/unban", false, ""},
		{users[1], "/dashboard/allow", true, "allow"},
		{users[2], "/dashboard/ban", false, ""},
		{users[2], "/dashboard/allow", false, ""},
	}
	for _, tc := range cases {
		loginAs(t, client, base, tc.user.Name, tc.user.Token)
		resp := authedPostForm(t, srv, client, base, tc.path, url.Values{
			"ip": {"203.0.113.50"}, "reason": {"matrix"},
		})
		closeBody(t, resp)
		denied := resp.StatusCode == http.StatusForbidden
		if denied != tc.wantDeny {
			t.Errorf("%s (%s) POST %s: status %d, wantDeny=%v",
				tc.user.Name, tc.user.Role, tc.path, resp.StatusCode, tc.wantDeny)
		}
		// Fresh session per case so roles never bleed between rows.
		resp = authedPostForm(t, srv, client, base, "/logout", url.Values{})
		closeBody(t, resp)
	}

	// Every denial above must be in the audit table, with actor and
	// action — and no token material anywhere.
	denials, err := srv.store.listRBACDenials(context.Background(), 100)
	if err != nil {
		t.Fatalf("listRBACDenials: %v", err)
	}
	wantDenials := 0
	for _, tc := range cases {
		if tc.wantDeny {
			wantDenials++
		}
	}
	if len(denials) != wantDenials {
		t.Errorf("audited denials = %d, want %d: %+v", len(denials), wantDenials, denials)
	}
	for _, d := range denials {
		if strings.Contains(d.Actor+d.Action+d.HeldRole, "token") {
			t.Errorf("denial row leaks token-like content: %+v", d)
		}
	}

	// Read surface: a viewer still sees every page.
	loginAs(t, client, base, "vera", users[0].Token)
	for _, page := range []string{"/dashboard", "/dashboard/bans", "/dashboard/allowlist", "/dashboard/events", "/dashboard/timeline"} {
		resp := doGet(t, client, base+page)
		closeBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("viewer GET %s: status %d, want 200", page, resp.StatusCode)
		}
	}
}

// TestRBAC_ImplicitDBAdmin: the legacy password admin keeps full power —
// backwards compatibility with the single-credential model.
func TestRBAC_ImplicitDBAdmin(t *testing.T) {
	srv, client, base, cleanup := newRBACTestServer(t)
	defer cleanup()

	loginAs(t, client, base, "admin", "db-admin-password-1234")
	resp := authedPostForm(t, srv, client, base, "/dashboard/allow", url.Values{
		"ip": {"203.0.113.51"}, "reason": {"compat"},
	})
	closeBody(t, resp)
	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("auth-DB admin must remain an implicit admin, got 403")
	}
}

// TestRBAC_ReloadReEvaluatesLiveSessions: a role change or removal in the
// user set applies to existing sessions on their next request.
func TestRBAC_ReloadReEvaluatesLiveSessions(t *testing.T) {
	srv, client, base, cleanup := newRBACTestServer(t)
	defer cleanup()

	users := rbacTestUsers()
	loginAs(t, client, base, "omar", users[1].Token)

	// Operator can reach the ban handler (non-403).
	resp := authedPostForm(t, srv, client, base, "/dashboard/ban", url.Values{
		"ip": {"203.0.113.52"}, "reason": {"pre-demotion"},
	})
	closeBody(t, resp)
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("operator denied before demotion")
	}

	// Demote omar to viewer: same session, next request refused.
	users[1].Role = "viewer"
	srv.ReloadUsers(users)
	resp = authedPostForm(t, srv, client, base, "/dashboard/ban", url.Values{
		"ip": {"203.0.113.53"}, "reason": {"post-demotion"},
	})
	closeBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("demoted user's live session kept operator power: %d", resp.StatusCode)
	}

	// Remove omar entirely: the session is terminated (redirect to login).
	srv.ReloadUsers([]AuthUser{users[0], users[2]})
	resp = doGet(t, client, base+"/dashboard")
	closeBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("deprovisioned user's session must be terminated, got %d", resp.StatusCode)
	}
}

// TestRBAC_CSRFStillEnforced: RBAC layering must not weaken the CSRF gate
// — an allowed role without a CSRF token is still refused.
func TestRBAC_CSRFStillEnforced(t *testing.T) {
	_, client, base, cleanup := newRBACTestServer(t)
	defer cleanup()

	users := rbacTestUsers()
	loginAs(t, client, base, "omar", users[1].Token)
	resp := doPostForm(t, client, base+"/dashboard/ban", url.Values{
		"ip": {"203.0.113.54"}, "reason": {"no-csrf"},
	})
	closeBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("missing CSRF token must still 403, got %d", resp.StatusCode)
	}
}

// TestRBAC_ActorInReason: mutation reasons are tagged with the acting
// user's NAME (never a token).
func TestRBAC_ActorInReason(t *testing.T) {
	t.Parallel()
	if got := dashboardActionReason("omar", "cleanup"); got != "dashboard:omar: cleanup" {
		t.Errorf("reason = %q", got)
	}
	if got := dashboardActionReason("", ""); got != "dashboard:admin" {
		t.Errorf("legacy reason = %q", got)
	}
}

// TestConfig_DashboardUsersValidation exercises the loader rules from this
// package's perspective (the config package owns the details).
func TestRBACStore_DenialPersistence(t *testing.T) {
	dir := t.TempDir()
	store, err := openAuthStore(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatalf("openAuthStore: %v", err)
	}
	defer store.close() //nolint:errcheck
	ctx := context.Background()
	if err := store.auditRBACDenial(ctx, "vera", "ban", "viewer"); err != nil {
		t.Fatalf("auditRBACDenial: %v", err)
	}
	rows, err := store.listRBACDenials(ctx, 10)
	if err != nil {
		t.Fatalf("listRBACDenials: %v", err)
	}
	if len(rows) != 1 || rows[0].Actor != "vera" || rows[0].Action != "ban" || rows[0].HeldRole != "viewer" {
		t.Errorf("rows = %+v", rows)
	}
}
