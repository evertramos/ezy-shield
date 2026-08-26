// SPDX-License-Identifier: AGPL-3.0-only

package dashboard

// Role-aware UI tests (issue #205): the header shows the logged-in user +
// role, and action forms are hidden for roles that lack the permission.
// Cosmetic only — the server-side matrix tests live in rbac_test.go.

import (
	"net/http"
	"strings"
	"testing"
)

func TestUI_HeaderShowsUserAndRole(t *testing.T) {
	_, client, base, cleanup := newRBACTestServer(t)
	defer cleanup()
	users := rbacTestUsers()

	loginAs(t, client, base, "vera", users[0].Token)
	body := readBody(t, doGet(t, client, base+"/dashboard"))
	if !strings.Contains(body, "vera (viewer)") {
		t.Errorf("header must show the current user and role, got:\n%s", firstKB(body))
	}
}

func TestUI_FormsFollowRole(t *testing.T) {
	_, client, base, cleanup := newRBACTestServer(t)
	defer cleanup()
	users := rbacTestUsers()

	// Viewer: no ban form, no unban buttons, no allow form.
	loginAs(t, client, base, "vera", users[0].Token)
	bans := readBody(t, doGet(t, client, base+"/dashboard/bans"))
	if strings.Contains(bans, `action="/dashboard/ban"`) || strings.Contains(bans, "Manual ban") {
		t.Errorf("viewer must not see the manual-ban form")
	}
	allow := readBody(t, doGet(t, client, base+"/dashboard/allowlist"))
	if strings.Contains(allow, `action="/dashboard/allow"`) {
		t.Errorf("viewer must not see the allowlist form")
	}

	// Operator: ban form yes, allow form no.
	loginAs(t, client, base, "omar", users[1].Token)
	bans = readBody(t, doGet(t, client, base+"/dashboard/bans"))
	if !strings.Contains(bans, `action="/dashboard/ban"`) {
		t.Errorf("operator must see the manual-ban form")
	}
	allow = readBody(t, doGet(t, client, base+"/dashboard/allowlist"))
	if strings.Contains(allow, `action="/dashboard/allow"`) {
		t.Errorf("operator must not see the allowlist form")
	}

	// Admin: everything.
	loginAs(t, client, base, "ada", users[2].Token)
	bans = readBody(t, doGet(t, client, base+"/dashboard/bans"))
	allow = readBody(t, doGet(t, client, base+"/dashboard/allowlist"))
	if !strings.Contains(bans, `action="/dashboard/ban"`) || !strings.Contains(allow, `action="/dashboard/allow"`) {
		t.Errorf("admin must see every action form")
	}
}

// TestUI_HidingIsCosmeticOnly re-asserts the AC's core caveat: a viewer
// crafting the POST by hand is still refused server-side.
func TestUI_HidingIsCosmeticOnly(t *testing.T) {
	srv, client, base, cleanup := newRBACTestServer(t)
	defer cleanup()
	users := rbacTestUsers()

	loginAs(t, client, base, "vera", users[0].Token)
	resp := authedPostForm(t, srv, client, base, "/dashboard/ban", map[string][]string{
		"ip": {"203.0.113.60"}, "reason": {"crafted"},
	})
	closeBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("hand-crafted POST from a viewer must still 403, got %d", resp.StatusCode)
	}
}

func firstKB(s string) string {
	if len(s) > 1024 {
		return s[:1024]
	}
	return s
}
