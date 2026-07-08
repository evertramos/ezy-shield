// Package dashboard implements the localhost-only web UI for EzyShield.
//
// The dashboard binds exclusively to loopback addresses (127.0.0.1 or ::1).
// Any attempt to bind elsewhere is refused before net.Listen is called, in
// line with the "no new network listeners" hard rule in AGENTS.md §2 and the
// control-surface doctrine in docs/SECURITY-REVIEW.md §6.
//
// Phase 1 scope: authentication scaffold — first-run admin bootstrap, login
// page, session cookie, placeholder index. Real-time views, WebSockets and
// manual ban/unban land in later phases. See docs/dashboard.md.
package dashboard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// DefaultAddr is the listen address used when the caller does not supply one.
// The port (9090) is chosen to avoid the common web-server ports and matches
// the value documented in docs/dashboard.md.
const DefaultAddr = "127.0.0.1:9090"

// DefaultSessionTimeout is the sliding idle timeout for authenticated
// sessions. Any request from a valid session extends the expiry.
const DefaultSessionTimeout = 30 * time.Minute

// Config controls dashboard server startup.
type Config struct {
	// Addr is the "host:port" the server binds to. Must resolve to a
	// loopback address (127.0.0.1, ::1, or the literal "localhost").
	Addr string
	// AuthDBPath is the SQLite file storing the admin password hash.
	// Created with mode 0600 on first use; the parent directory is created
	// with mode 0700 if missing.
	AuthDBPath string
	// SessionTimeout is the idle timeout after which sessions expire.
	SessionTimeout time.Duration
	// Logger is the structured logger for server events. If nil,
	// slog.Default() is used.
	Logger *slog.Logger
}

// Server is a localhost-only HTTP server for the EzyShield dashboard.
type Server struct {
	cfg      Config
	logger   *slog.Logger
	store    *authStore
	sessions *sessionStore
	mux      *http.ServeMux
	srv      *http.Server
}

// New constructs a Server and opens the auth store. It rejects non-loopback
// bind addresses at construction time so misconfiguration surfaces before any
// listener is opened.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = DefaultSessionTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.AuthDBPath == "" {
		return nil, errors.New("dashboard: AuthDBPath is required")
	}
	if err := checkLoopback(cfg.Addr); err != nil {
		return nil, fmt.Errorf("dashboard: %w", err)
	}
	store, err := openAuthStore(cfg.AuthDBPath)
	if err != nil {
		return nil, fmt.Errorf("dashboard: open auth store: %w", err)
	}
	s := &Server{
		cfg:      cfg,
		logger:   cfg.Logger,
		store:    store,
		sessions: newSessionStore(cfg.SessionTimeout),
	}
	s.mux = s.routes()
	return s, nil
}

// EnsureAdmin creates the default "admin" account when the store is empty and
// returns the freshly generated password. The password is returned exactly
// once — the store persists only the PBKDF2 hash — and the caller is
// responsible for presenting it to the operator before it is discarded.
func (s *Server) EnsureAdmin(ctx context.Context) (password string, created bool, err error) {
	exists, err := s.store.HasAdmin(ctx)
	if err != nil {
		return "", false, err
	}
	if exists {
		return "", false, nil
	}
	pw, err := generatePassword()
	if err != nil {
		return "", false, err
	}
	hash, err := hashPassword(pw)
	if err != nil {
		return "", false, err
	}
	if err := s.store.SetAdmin(ctx, "admin", hash); err != nil {
		return "", false, err
	}
	return pw, true, nil
}

// Run binds the listener and serves HTTP until ctx is cancelled.
// The loopback check is re-run here as defence in depth against callers that
// mutated cfg.Addr between New and Run.
func (s *Server) Run(ctx context.Context) error {
	if err := checkLoopback(s.cfg.Addr); err != nil {
		return fmt.Errorf("dashboard: %w", err)
	}
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("dashboard: listen %s: %w", s.cfg.Addr, err)
	}
	return s.serve(ctx, ln)
}

// Serve serves HTTP on the supplied listener. It is exported for tests that
// need to inject a listener bound to an OS-chosen port; production callers
// should use Run instead.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if err := checkListenerLoopback(ln); err != nil {
		return fmt.Errorf("dashboard: %w", err)
	}
	return s.serve(ctx, ln)
}

func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	s.srv = &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("dashboard listening", "addr", ln.Addr().String())
		err := s.srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("dashboard: shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// Close releases the underlying auth store handle.
func (s *Server) Close() error {
	return s.store.Close()
}

// Handler exposes the mux for tests that exercise routes without a listener.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// checkLoopback rejects any bind address that does not resolve to a loopback
// interface. The literal string "localhost" is accepted so operators can use
// it interchangeably with 127.0.0.1.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("addr %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("addr %q: empty host; dashboard must bind to a loopback address (127.0.0.1 or ::1)", addr)
	}
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("addr %q: host must be a loopback IP or \"localhost\"", addr)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("addr %q: refusing non-loopback bind; dashboard is localhost-only (AGENTS.md §2)", addr)
	}
	return nil
}

func checkListenerLoopback(ln net.Listener) error {
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("listener %s: not a TCP listener", ln.Addr())
	}
	ip, ok := netip.AddrFromSlice(tcpAddr.IP)
	if !ok || !ip.IsLoopback() {
		return fmt.Errorf("listener %s: refusing non-loopback bind; dashboard is localhost-only (AGENTS.md §2)", tcpAddr.IP)
	}
	return nil
}
