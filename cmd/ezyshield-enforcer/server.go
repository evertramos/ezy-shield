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
	"os/user"
	"strconv"
	"sync"

	"github.com/evertramos/ezy-shield/internal/enforce"
)

// validVerbs is the complete, fixed set of verbs the enforcer accepts.
// Anything outside this set is rejected to prevent pass-through of arbitrary
// nft commands (SECURITY-REVIEW.md §3).
var validVerbs = map[string]bool{
	"add": true, "del": true, "flush": true, "list": true, "ping": true,
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

// daemonGroupName is the unix group the EzyShield daemon runs as. The enforcer
// socket is chowned to root:<daemonGroupName> 0660 so the unprivileged daemon
// can connect while non-group users cannot. Kept in sync with the same constant
// in cmd/ezyshield/ownership.go (issue #92).
const daemonGroupName = "ezyshield"

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

	// Chown to root:ezyshield first, then chmod 0660 — owner rw, group rw,
	// other none (SECURITY-REVIEW.md §3). Standard fail2ban/sshguard pattern:
	// admins in the daemon group can use the socket without sudo (issue #6).
	chownEnforcerSocket(s.socketPath)
	if err := os.Chmod(s.socketPath, 0o660); err != nil { //nolint:gosec // G302: 0660 is intentional; socket is group-restricted to 'ezyshield'
		_ = ln.Close()
		return fmt.Errorf("enforcer: chmod socket: %w", err)
	}

	s.ln = ln
	return nil
}

// chownEnforcerSocket chowns path to root:ezyshield. If the group is missing
// (e.g., a container without 'ezyshield init' run) it falls back to the current
// process uid/gid so the socket is still owned by something usable, and logs a
// warning so the operator notices.
func chownEnforcerSocket(path string) {
	g, lookupErr := user.LookupGroup(daemonGroupName)
	if lookupErr != nil {
		uid, gid := os.Getuid(), os.Getgid()
		slog.Warn("enforcer: ezyshield group not found, falling back to current uid:gid — daemon (User=ezyshield) cannot connect until 'ezyshield init' creates the group",
			slog.String("path", path), slog.Int("uid", uid), slog.Int("gid", gid),
			slog.String("err", lookupErr.Error()))
		if err := os.Chown(path, uid, gid); err != nil {
			slog.Warn("enforcer: socket chown fallback failed",
				slog.String("path", path), slog.String("err", err.Error()))
		}
		return
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		slog.Warn("enforcer: invalid group id for ezyshield",
			slog.String("gid", g.Gid), slog.String("err", err.Error()))
		return
	}
	if err := os.Chown(path, 0, gid); err != nil {
		slog.Warn("enforcer: could not chown socket to root:ezyshield",
			slog.Int("gid", gid), slog.String("err", err.Error()))
		return
	}
	slog.Info("enforcer: socket ready",
		slog.String("path", path),
		slog.String("owner", "root:"+daemonGroupName),
		slog.String("mode", "0660"))
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
