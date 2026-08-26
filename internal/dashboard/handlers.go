package dashboard

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

const sessionCookieName = "ezyshield_dashboard"

// maxLoginUsernameLen bounds the username accepted at /login before any store
// lookup or PBKDF2 work. Admin usernames are short; anything longer is a
// brute-force probe (issue #360).
const maxLoginUsernameLen = 64

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	// Logout goes through the same auth + CSRF gates as every other POST:
	// one invariant for all mutations (issue #86). An expired session lands
	// on /login via requireAuth — the outcome a stale "Sign out" click
	// wants anyway.
	mux.HandleFunc("POST /logout", s.requireRole("logout", s.handleLogout))
	// Root redirects authed sessions to the Phase 2 status page and drops
	// unauthed callers on /login.
	mux.HandleFunc("GET /", s.requireRole("view", s.handleRootRedirect))
	mux.HandleFunc("GET /dashboard", s.requireRole("view", s.handleStatusPage))
	mux.HandleFunc("GET /dashboard/bans", s.requireRole("view", s.handleBansPage))
	mux.HandleFunc("GET /dashboard/allowlist", s.requireRole("view", s.handleAllowlistPage))
	mux.HandleFunc("GET /dashboard/events", s.requireRole("view", s.handleEventsPage))
	mux.HandleFunc("GET /dashboard/timeline", s.requireRole("view", s.handleTimelinePage))
	// RBAC (issue #204): every mutating route names its action from the
	// permission table in rbac.go — enforcement is server-side here; any
	// UI hiding is cosmetic only.
	mux.HandleFunc("POST /dashboard/ban", s.requireRole("ban", s.handleBanPost))
	mux.HandleFunc("POST /dashboard/unban", s.requireRole("unban", s.handleUnbanPost))
	mux.HandleFunc("POST /dashboard/allow", s.requireRole("allow", s.handleAllowPost))
	// WebSocket endpoint for live-update pushes. The upgrade is auth-
	// gated by the same session cookie check as every /dashboard route,
	// so an unauthenticated browser cannot open the socket. Push-only —
	// no client command ever mutates state through it, hence viewer tier.
	mux.HandleFunc("GET /dashboard/ws", s.requireRole("ws", s.handleWebSocket))
	// Prometheus exposition (issue #183): session auth by default;
	// dashboard.metrics_auth: false opens it for scrapers — acceptable
	// only because the listener is loopback-only. Throttled either way
	// inside handleMetrics.
	if s.cfg.MetricsOpen {
		mux.HandleFunc("GET /metrics", s.handleMetrics)
	} else {
		mux.HandleFunc("GET /metrics", s.requireRole("metrics", s.handleMetrics))
	}
	return mux
}

// requireRole layers RBAC on top of requireAuth: the session's user must
// currently hold at least the role the permission table demands for
// action. Denials are audited (actor, action — never any token) and answer
// 403. A session whose user vanished from config is terminated.
func (s *Server) requireRole(action string, h http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		info, ok := sessionFromContext(r.Context())
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		role, known := s.roleFor(r.Context(), info.Username)
		if !known {
			// The user was deprovisioned while logged in: kill the
			// session rather than downgrading it silently.
			if c, err := r.Cookie(sessionCookieName); err == nil {
				s.sessions.Delete(c.Value)
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if need := requiredRole(action); role < need {
			s.auditDenied(r.Context(), info.Username, action, role)
			http.Error(w, "forbidden: this action requires the "+need.String()+" role", http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

// roleFor resolves the CURRENT role of a logged-in username: config users
// from the live user set (so reloads apply immediately), and the auth-DB
// password admin as the documented implicit RoleAdmin fallback.
func (s *Server) roleFor(ctx context.Context, username string) (Role, bool) {
	if role, ok := s.users.roleOf(username); ok {
		return role, true
	}
	if _, err := s.store.getAdminHash(ctx, username); err == nil {
		return RoleAdmin, true
	}
	return RoleViewer, false
}

// auditDenied records one 403 in the dashboard's audit table and logs it.
// Actor and action only — never tokens.
func (s *Server) auditDenied(ctx context.Context, actor, action string, held Role) {
	s.logger.Warn("dashboard: rbac denied", "actor", actor, "action", action, "role", held.String())
	if err := s.store.auditRBACDenial(ctx, actor, action, held.String()); err != nil {
		s.logger.Error("dashboard: rbac audit write", "err", err)
	}
}

// requireAuth wraps h so unauthenticated requests are redirected to /login.
// On success it also attaches the sessionInfo (username + CSRF) to the
// request context so downstream handlers can validate CSRF and embed the
// token in server-rendered forms without a second store lookup.
func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		info, ok := s.sessions.Lookup(c.Value)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r.WithContext(withSession(r.Context(), info)))
	}
}

func (s *Server) handleLoginGet(w http.ResponseWriter, _ *http.Request) {
	if err := renderLogin(w, ""); err != nil {
		s.logger.Error("render login", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	// Reject implausibly long usernames before any store lookup or PBKDF2:
	// admin usernames are short, and an unbounded attacker-supplied key would
	// otherwise be stored in the throttle map and burn a decoy hash (issue
	// #360). A generic 401 keeps existing/unknown usernames indistinguishable.
	if len(username) > maxLoginUsernameLen {
		w.WriteHeader(http.StatusUnauthorized)
		if err := renderLogin(w, "Invalid credentials."); err != nil {
			s.logger.Error("render login", "err", err)
		}
		return
	}

	// Check the throttle before doing any store work. A locked-out
	// account cannot burn PBKDF2 CPU on brute-force attempts, and the
	// response is a fixed banner so the operator learns why.
	if !s.throttle.Allow(username) {
		w.WriteHeader(http.StatusTooManyRequests)
		if err := renderLogin(w, "Too many failed attempts. Try again in a minute."); err != nil {
			s.logger.Error("render login", "err", err)
		}
		return
	}

	// Config-provisioned RBAC users first (issue #204): name + per-user
	// token, constant-time over digest comparisons. On a miss we FALL
	// THROUGH to the auth-DB path below, which pays the full PBKDF2 (or
	// decoy) cost — so a failed config-user attempt is indistinguishable in
	// timing from any other failed login.
	if u, ok := s.users.authenticate(username, password); ok {
		s.throttle.Clear(username)
		s.createSessionAndRedirect(w, r, u.name)
		return
	}

	hash, err := s.store.getAdminHash(r.Context(), username)
	switch {
	case err == nil:
	case errors.Is(err, errAdminNotFound):
		// Substitute a valid-format decoy hash so verifyPassword still
		// pays the full ~300 ms PBKDF2 cost. Without this substitution
		// an attacker could distinguish existing usernames from
		// unknown ones by response time (CWE-208).
		hash = s.decoyHash
	default:
		s.logger.Error("auth lookup", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ok := verifyPassword(hash, password)
	if !ok {
		s.throttle.RecordFailure(username)
		w.WriteHeader(http.StatusUnauthorized)
		if err := renderLogin(w, "Invalid credentials."); err != nil {
			s.logger.Error("render login", "err", err)
		}
		return
	}
	s.throttle.Clear(username)
	s.createSessionAndRedirect(w, r, username)
}

// createSessionAndRedirect finishes a successful login: session + cookie.
func (s *Server) createSessionAndRedirect(w http.ResponseWriter, r *http.Request, username string) {
	token, _, err := s.sessions.Create(username)
	if err != nil {
		s.logger.Error("session create", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Secure is set so that operators fronting the dashboard with TLS
	// through a reverse proxy or Cloudflare Tunnel get browser refusal on
	// plaintext downgrade. Modern browsers treat http://localhost as a
	// secure context, so Secure=true still delivers the cookie on the
	// default loopback deployment.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.requireCSRF(w, r) {
		return
	}
	if c, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleRootRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
