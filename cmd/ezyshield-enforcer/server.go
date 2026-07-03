package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/ownership"
)

// validVerbs is the complete, fixed set of verbs the enforcer accepts.
// Anything outside this set is rejected to prevent pass-through of arbitrary
// nft commands (SECURITY-REVIEW.md §3).
var validVerbs = map[string]bool{
	"add": true, "del": true, "flush": true, "list": true, "ping": true,
	"allow_add": true, "allow_del": true, "allow_list": true, "allow_flush": true,
}

// Server is the enforcer unix-socket server.
// It maintains an in-memory copy of the blocked set so that "list" is fast
// without re-parsing nft output on every call.
type Server struct {
	socketPath string
	run        nftRunner

	mu      sync.RWMutex
	blocked map[string]bool // canonical IP/CIDR strings currently in nft set

	ln net.Listener
}

// newServer creates a Server with the given socket path and nft runner.
// Call listen() then serve() to start handling requests.
func newServer(socketPath string, run nftRunner) *Server {
	return &Server{
		socketPath: socketPath,
		run:        run,
		blocked:    make(map[string]bool),
	}
}

// socketPath returns the unix socket path (for tests to connect to).
func (s *Server) sockPath() string { return s.socketPath }

// listen creates the unix socket with 0660 permissions and group=ezyshield.
// The socket is root-owned so only root (or group ezyshield) can connect
// (issue #92, SECURITY-REVIEW.md §3).
func (s *Server) listen(ctx context.Context) error {
	// Remove a stale socket from a previous run.
	_ = os.Remove(s.socketPath)

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("enforcer: listen %s: %w", s.socketPath, err)
	}

	// Set the socket group to ezyshield, then chmod 0660 — owner rw, group rw,
	// other none (SECURITY-REVIEW.md §3). The owner is left unchanged so this
	// never needs CAP_CHOWN: under systemd the unit sets Group=ezyshield, so the
	// socket is created root:ezyshield and this is effectively a no-op; run
	// manually as root it sets the group directly. Either way the daemon can
	// connect without sudo (issue #6).
	if err := ownership.ChownToGroup(s.socketPath, ownership.Group); err != nil {
		slog.Warn("enforcer: could not set socket group; daemon may be unable to connect until 'ezyshield init' creates the group",
			slog.String("path", s.socketPath), slog.String("group", ownership.Group), slog.String("err", err.Error()))
	}
	if err := os.Chmod(s.socketPath, 0o660); err != nil { //nolint:gosec // G302: 0660 is intentional; socket is group-restricted to 'ezyshield'
		_ = ln.Close()
		return fmt.Errorf("enforcer: chmod socket: %w", err)
	}

	s.ln = ln
	return nil
}

// init initialises the nftables table/set/chain and loads the current set
// state into the in-memory cache.
func (s *Server) init(ctx context.Context) error {
	if err := initTable(ctx, s.run); err != nil {
		return fmt.Errorf("enforcer: init nft table: %w", err)
	}
	ips, err := nftList(ctx)
	if err != nil {
		return fmt.Errorf("enforcer: load existing set state: %w", err)
	}
	s.mu.Lock()
	for _, ip := range ips {
		s.blocked[ip] = true
	}
	s.mu.Unlock()
	slog.Info("enforcer: nft table ready", "existing_entries", len(ips))
	return nil
}

// serve accepts connections until ctx is cancelled.
func (s *Server) serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("enforcer: accept: %w", err)
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close() //nolint:errcheck

	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		var req enforce.Request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			s.writeResp(conn, enforce.Response{OK: false, Error: "invalid JSON"})
			continue
		}
		resp := s.dispatch(ctx, req)
		s.writeResp(conn, resp)
	}
}

// dispatch validates and executes a single request.
func (s *Server) dispatch(ctx context.Context, req enforce.Request) enforce.Response {
	// §3: reject any verb not in the fixed set.
	if !validVerbs[req.Verb] {
		slog.WarnContext(ctx, "enforcer: rejected unknown verb", "verb", req.Verb)
		return enforce.Response{OK: false, Error: fmt.Sprintf("unknown verb %q", req.Verb)}
	}

	switch req.Verb {
	case "ping":
		return enforce.Response{OK: true}

	case "list":
		s.mu.RLock()
		ips := make([]string, 0, len(s.blocked))
		for ip := range s.blocked {
			ips = append(ips, ip)
		}
		s.mu.RUnlock()
		return enforce.Response{OK: true, IPs: ips}

	case "flush":
		if err := nftFlush(ctx, s.run); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		s.mu.Lock()
		s.blocked = make(map[string]bool)
		s.mu.Unlock()
		return enforce.Response{OK: true}

	case "add":
		if err := validateIP(req.IP); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		if err := nftAdd(ctx, s.run, req.IP, req.TTLSeconds); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		s.mu.Lock()
		s.blocked[req.IP] = true
		s.mu.Unlock()
		return enforce.Response{OK: true}

	case "del":
		if err := validateIP(req.IP); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		if err := nftDel(ctx, s.run, req.IP); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		s.mu.Lock()
		delete(s.blocked, req.IP)
		s.mu.Unlock()
		return enforce.Response{OK: true}

	case "allow_add":
		if err := validateIP(req.IP); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		if err := nftAddAllow(ctx, s.run, req.IP); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		return enforce.Response{OK: true}

	case "allow_del":
		if err := validateIP(req.IP); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		if err := nftDelAllow(ctx, s.run, req.IP); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		return enforce.Response{OK: true}

	case "allow_list":
		ips, err := nftListAllow(ctx)
		if err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		return enforce.Response{OK: true, IPs: ips}

	case "allow_flush":
		if err := nftFlushAllow(ctx, s.run); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		return enforce.Response{OK: true}
	}

	// unreachable given the validVerbs check above
	return enforce.Response{OK: false, Error: "internal error"}
}

func (s *Server) writeResp(conn net.Conn, resp enforce.Response) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		slog.Warn("enforcer: write response failed", "err", err)
	}
}

// validateIP checks that ip is a well-formed netip.Addr or netip.Prefix.
// This prevents raw nft syntax from being injected into the nft scripts
// (SECURITY-REVIEW.md §3, AGENTS.md Hard Rule §4).
func validateIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("ip field is required")
	}
	if _, err := netip.ParseAddr(ip); err == nil {
		return nil
	}
	if _, err := netip.ParsePrefix(ip); err == nil {
		return nil
	}
	return fmt.Errorf("%q is not a valid IP address or CIDR prefix", ip)
}
