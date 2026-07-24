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
	"github.com/evertramos/ezy-shield/internal/nftnames"
	"github.com/evertramos/ezy-shield/internal/ownership"
)

// validVerbs is the complete, fixed set of verbs the enforcer accepts.
// Anything outside this set is rejected to prevent pass-through of arbitrary
// nft commands (SECURITY-REVIEW.md §3).
var validVerbs = map[string]bool{
	"add": true, "del": true, "flush": true, "list": true, "ping": true, "caps": true,
	"allow_add": true, "allow_del": true, "allow_list": true, "allow_flush": true,
}

// Server is the enforcer unix-socket server.
// It maintains an in-memory copy of the blocked set so that "list" is fast
// without re-parsing nft output on every call.
type Server struct {
	socketPath string
	run        nftRunner
	runSs      ssRunner // pre-ban TCP session teardown (issue #30)
	// listFn reads the current blocked-set contents (defaults to the real
	// `nft list set` exec). Injectable so unit tests can exercise the
	// name-switch path without a real nft binary on the host.
	listFn func(ctx context.Context, n nftnames.Names) ([]string, error)

	mu      sync.RWMutex
	blocked map[string]bool // canonical IP/CIDR strings currently in nft set

	// names is the active nftables name set (issue #268). Boot initializes
	// the defaults; the first request that resolves to a DIFFERENT name set
	// switches once (init new table, reload cache, drop the empty default
	// table) and pins — after pinning, requests naming anything else are
	// rejected. One enforcer process manages exactly one table: the blocked
	// cache above and the anti-lockout rule layout depend on that.
	names  nftnames.Names
	pinned bool

	ln net.Listener
}

// newServer creates a Server with the given socket path and nft runner.
// Call listen() then serve() to start handling requests.
func newServer(socketPath string, run nftRunner) *Server {
	defaults, _ := nftnames.Resolve("", "") // cannot fail for empty inputs
	return &Server{
		socketPath: socketPath,
		run:        run,
		runSs:      realSsRunner,
		listFn:     nftList,
		blocked:    make(map[string]bool),
		names:      defaults,
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
	if err := initTable(ctx, s.run, s.names); err != nil {
		return fmt.Errorf("enforcer: init nft table: %w", err)
	}
	ips, err := s.listFn(ctx, s.names)
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

	// Resolve + pin the nftables names this request operates on (issue
	// #268). Runs before the verb switch so every nft-touching verb goes
	// through the same gate; ping/caps skip it (they touch no nft state and
	// must keep working for probes regardless of name pinning).
	names := s.names
	if req.Verb != "ping" && req.Verb != "caps" {
		var resp *enforce.Response
		names, resp = s.resolveNames(ctx, req)
		if resp != nil {
			return *resp
		}
	}

	switch req.Verb {
	case "ping":
		return enforce.Response{OK: true}

	case "caps":
		return enforce.Response{OK: true, Features: []string{enforce.FeatureCustomNames}}

	case "list":
		s.mu.RLock()
		ips := make([]string, 0, len(s.blocked))
		for ip := range s.blocked {
			ips = append(ips, ip)
		}
		s.mu.RUnlock()
		return enforce.Response{OK: true, IPs: ips}

	case "flush":
		if err := nftFlush(ctx, s.run, names); err != nil {
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
		if err := nftAdd(ctx, s.run, names, req.IP, req.TTLSeconds); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		s.mu.Lock()
		s.blocked[req.IP] = true
		s.mu.Unlock()
		// Kill any TCP sessions already established from this peer (issue #30).
		// Only for single addresses — `ss -K dst` does not accept CIDR, and
		// per-address teardown for a /24 would fan out into thousands of no-op
		// calls. CIDR follow-up is tracked separately. Best-effort: the
		// helper swallows all errors so a failed teardown never rolls back
		// the committed nft ban (Hard Rule §1: safety invariant).
		if _, err := netip.ParseAddr(req.IP); err == nil && s.runSs != nil {
			_ = killSocketsForIP(ctx, s.runSs, req.IP)
		}
		return enforce.Response{OK: true}

	case "del":
		if err := validateIP(req.IP); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		if err := nftDel(ctx, s.run, names, req.IP); err != nil {
			// Typed signal: nft-native timeout (or an out-of-band flush) beat
			// us to it. Desired end state (absent) is achieved — respond OK
			// with a stable code the client can trace at DEBUG instead of
			// ERROR (issue #39). Sync the in-memory cache so we don't keep
			// re-issuing deletes on subsequent Sync ticks.
			if errors.Is(err, errElementAbsent) {
				s.mu.Lock()
				delete(s.blocked, req.IP)
				s.mu.Unlock()
				return enforce.Response{OK: true, Code: enforce.CodeAlreadyAbsent}
			}
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
		if err := nftAddAllow(ctx, s.run, names, req.IP); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		return enforce.Response{OK: true}

	case "allow_del":
		if err := validateIP(req.IP); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		if err := nftDelAllow(ctx, s.run, names, req.IP); err != nil {
			// Symmetric with "del": already-absent maps to the typed OK code.
			if errors.Is(err, errElementAbsent) {
				return enforce.Response{OK: true, Code: enforce.CodeAlreadyAbsent}
			}
			return enforce.Response{OK: false, Error: err.Error()}
		}
		return enforce.Response{OK: true}

	case "allow_list":
		ips, err := nftListAllow(ctx, names)
		if err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		return enforce.Response{OK: true, IPs: ips}

	case "allow_flush":
		if err := nftFlushAllow(ctx, s.run, names); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		return enforce.Response{OK: true}
	}

	// unreachable given the validVerbs check above
	return enforce.Response{OK: false, Error: "internal error"}
}

// resolveNames maps a request's Table/Set fields onto the active name set.
// Empty fields mean "defaults" for wire-compat with older daemons. The first
// request resolving to a non-active name set triggers a one-time switch;
// afterwards the names are pinned for the process lifetime and conflicting
// requests are rejected with an actionable error. Returns a non-nil response
// on rejection.
func (s *Server) resolveNames(ctx context.Context, req enforce.Request) (nftnames.Names, *enforce.Response) {
	want, err := nftnames.Resolve(req.Table, req.Set)
	if err != nil {
		// Names failed the strict validation at THIS trust boundary — never
		// proceed, never echo anything nft-adjacent back beyond the message.
		slog.WarnContext(ctx, "enforcer: rejected invalid nftables names", "err", err.Error())
		return nftnames.Names{}, &enforce.Response{OK: false, Error: err.Error()}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if want == s.names {
		s.pinned = true
		return want, nil
	}
	if s.pinned {
		e := fmt.Sprintf("enforcer is active with table %q / set %q; restart ezyshield-enforcer to apply table %q / set %q",
			s.names.Table, s.names.Set4, want.Table, want.Set4)
		slog.WarnContext(ctx, "enforcer: rejected conflicting nftables names", "active_table", s.names.Table, "requested_table", want.Table)
		return nftnames.Names{}, &enforce.Response{OK: false, Error: e}
	}

	if err := s.switchNamesLocked(ctx, want); err != nil {
		return nftnames.Names{}, &enforce.Response{OK: false, Error: err.Error()}
	}
	return want, nil
}

// switchNamesLocked moves the enforcer from the boot-time default table to
// the operator-configured one: init the new table's layout, reload the
// blocked cache from it, best-effort delete the (empty, just-created)
// default table, and pin. Caller holds s.mu.
func (s *Server) switchNamesLocked(ctx context.Context, want nftnames.Names) error {
	old := s.names
	if err := initTable(ctx, s.run, want); err != nil {
		return fmt.Errorf("enforcer: init table %q: %w", want.Table, err)
	}
	ips, err := s.listFn(ctx, want)
	if err != nil {
		return fmt.Errorf("enforcer: load state from table %q: %w", want.Table, err)
	}
	s.blocked = make(map[string]bool, len(ips))
	for _, ip := range ips {
		s.blocked[ip] = true
	}
	s.names = want
	s.pinned = true

	// The default table was created seconds ago at boot and never held
	// elements under this configuration — delete it so `nft list ruleset`
	// shows one EzyShield table, not two. Best-effort: a failure here is
	// cosmetic, enforcement already happens in the new table.
	if old.IsDefault() {
		if err := s.run(ctx, []byte("delete table "+old.Table+"\n")); err != nil {
			slog.WarnContext(ctx, "enforcer: could not remove default table after switch (cosmetic)",
				"table", old.Table, "err", err.Error())
		}
	}
	slog.InfoContext(ctx, "enforcer: switched nftables names",
		"table", want.Table, "set", want.Set4, "existing_entries", len(ips))
	return nil
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
