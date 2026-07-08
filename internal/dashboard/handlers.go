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
	mux.HandleFunc("GET /", s.requireAuth(s.handleIndex))
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

	hash, err := s.store.GetAdminHash(r.Context(), username)
	ok := false
	switch {
	case err == nil:
		ok = verifyPassword(hash, password)
	case errors.Is(err, errAdminNotFound):
		// Fall through to the invalid-credentials response so the login
		// page cannot be used to enumerate valid usernames.
	default:
		s.logger.Error("auth lookup", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
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
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// Secure is intentionally false: the dashboard is bound to
		// loopback only, so plaintext HTTP is the expected transport.
		// Operators fronting the dashboard with TLS via a reverse
		// proxy should terminate outside the dashboard process.
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
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	if err := renderIndex(w); err != nil {
		s.logger.Error("render index", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
