// SPDX-License-Identifier: AGPL-3.0-only

package dashboard

// Role-based access control for the dashboard (issue #204).
//
// Model: viewer (read-only) < operator (+ ban/unban) < admin (+ allowlist
// mutations, arm/disarm, policy edit). The permission table below is THE
// single source of truth, enforced server-side on every mutating handler —
// any UI hiding (#205) is cosmetic only. Deny by default: an action absent
// from the table requires admin.
//
// Authentication: config-provisioned users carry a per-user token
// (env-reference resolved outside this package). Token comparison is
// constant-time over fixed-size SHA-256 digests — the compare cost is
// independent of both the token content and its length, and every stored
// user is compared on every attempt (no early exit on name match), so
// timing does not leak which usernames exist (CWE-208 discipline mirrors
// the login decoy hash).

import (
	"crypto/sha256"
	"crypto/subtle"
	"sync"
)

// Role is an ordered privilege level; higher includes lower.
type Role int8

const (
	// RoleViewer can read every page and stream, and nothing else.
	RoleViewer Role = iota
	// RoleOperator adds ban/unban.
	RoleOperator
	// RoleAdmin adds allowlist mutations, arm/disarm, and policy edits —
	// and is the deny-by-default requirement for any unclassified action.
	RoleAdmin
)

// String renders the role for UI/audit (never anything secret).
func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	default:
		return "admin"
	}
}

// ParseRole maps the config enum; ok=false for anything unknown.
func ParseRole(s string) (Role, bool) {
	switch s {
	case "viewer":
		return RoleViewer, true
	case "operator":
		return RoleOperator, true
	case "admin":
		return RoleAdmin, true
	}
	return RoleAdmin, false
}

// actionRoles is the permission table — the ONE place where actions map to
// minimum roles. Every route registration names its action; new mutating
// endpoints MUST be added here (or they cost admin, by requiredRole).
var actionRoles = map[string]Role{
	// Read surface.
	"view":    RoleViewer,
	"ws":      RoleViewer,
	"metrics": RoleViewer,
	"logout":  RoleViewer,
	// Operator surface.
	"ban":   RoleOperator,
	"unban": RoleOperator,
	// Admin surface.
	"allow":       RoleAdmin,
	"unallow":     RoleAdmin,
	"arm":         RoleAdmin,
	"disarm":      RoleAdmin,
	"policy_edit": RoleAdmin,
}

// requiredRole returns the minimum role for an action. Unknown actions
// require admin — deny by default, so a new endpoint added without a table
// entry is locked down rather than open.
func requiredRole(action string) Role {
	if r, ok := actionRoles[action]; ok {
		return r
	}
	return RoleAdmin
}

// AuthUser is one resolved dashboard user handed to New by the caller
// (token already resolved from its env reference; this package never sees
// the reference and never logs the value).
type AuthUser struct {
	Name  string
	Role  string
	Token string
}

// rbacUser is the internal form: the token survives only as a SHA-256
// digest, so neither the user set nor any accidental dump can reveal it.
type rbacUser struct {
	name      string
	role      Role
	tokenHash [sha256.Size]byte
}

// userSet holds the current config-provisioned users. Replaceable at
// runtime (ReloadUsers), and roles are looked up per request — a reload
// re-evaluates every live session's role immediately.
type userSet struct {
	mu    sync.RWMutex
	users []rbacUser
}

func newUserSet(users []AuthUser) *userSet {
	s := &userSet{}
	s.replace(users)
	return s
}

func (s *userSet) replace(users []AuthUser) {
	next := make([]rbacUser, 0, len(users))
	for _, u := range users {
		role, ok := ParseRole(u.Role)
		if !ok {
			// Config validation rejects unknown roles at load; if one
			// slips through anyway, fail toward least privilege.
			role = RoleViewer
		}
		next = append(next, rbacUser{
			name:      u.Name,
			role:      role,
			tokenHash: sha256.Sum256([]byte(u.Token)),
		})
	}
	s.mu.Lock()
	s.users = next
	s.mu.Unlock()
}

// authenticate resolves (name, token) to a user. Constant-time: the token
// compare runs over fixed-size digests for EVERY stored user regardless of
// name matches, and the result is accumulated without branching, so
// response timing does not reveal which names exist or where a mismatch
// happened.
func (s *userSet) authenticate(name, token string) (rbacUser, bool) {
	digest := sha256.Sum256([]byte(token))
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matched rbacUser
	found := 0
	for _, u := range s.users {
		nameOK := subtle.ConstantTimeCompare([]byte(u.name), []byte(name))
		tokenOK := subtle.ConstantTimeCompare(u.tokenHash[:], digest[:])
		if nameOK&tokenOK == 1 {
			matched = u
			found = 1
		}
	}
	return matched, found == 1
}

// roleOf returns the CURRENT role of a config user; ok=false when the name
// is not (or no longer) provisioned. Called per request so config reloads
// take effect on live sessions.
func (s *userSet) roleOf(name string) (Role, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.name == name {
			return u.role, true
		}
	}
	return RoleViewer, false
}

// empty reports whether any config users are provisioned at the moment.
func (s *userSet) empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users) == 0
}
