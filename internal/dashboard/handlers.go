package dashboard

import (
	"errors"
	"net/http"
	"strings"
)

const sessionCookieName = "ezyshield_dashboard"

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("POST /logout", s.handleLogout)
	// Root redirects authed sessions to the Phase 2 status page and drops
	// unauthed callers on /login.
	mux.HandleFunc("GET /", s.requireAuth(s.handleRootRedirect))
	mux.HandleFunc("GET /dashboard", s.requireAuth(s.handleStatusPage))
	mux.HandleFunc("GET /dashboard/bans", s.requireAuth(s.handleBansPage))
	mux.HandleFunc("GET /dashboard/allowlist", s.requireAuth(s.handleAllowlistPage))
	mux.HandleFunc("GET /dashboard/events", s.requireAuth(s.handleEventsPage))
	mux.HandleFunc("POST /dashboard/ban", s.requireAuth(s.handleBanPost))
	mux.HandleFunc("POST /dashboard/unban", s.requireAuth(s.handleUnbanPost))
	mux.HandleFunc("POST /dashboard/allow", s.requireAuth(s.handleAllowPost))
	// WebSocket endpoint for live-update pushes. The upgrade is auth-
	// gated by the same session cookie check as every /dashboard route,
	// so an unauthenticated browser cannot open the socket.
	mux.HandleFunc("GET /dashboard/ws", s.requireAuth(s.handleWebSocket))
	return mux
}

// requireAuth wraps h so unauthenticated requests are redirected to /login.
func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if _, ok := s.sessions.Get(c.Value); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r)
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
		w.WriteHeader(http.StatusUnauthorized)
		if err := renderLogin(w, "Invalid credentials."); err != nil {
			s.logger.Error("render login", "err", err)
		}
		return
	}

	token, err := s.sessions.Create(username)
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
