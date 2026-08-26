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
	"time"

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
	"feeds_sync": true,
	"netcheck":   true,
}

// maxRequestBytes bounds one request line. Everything except feeds_sync fits
// in a few hundred bytes; feeds_sync carries up to enforce.MaxFeedElements
// entries (~45 bytes each on the wire), so 8MiB gives comfortable headroom
// while still bounding a hostile writer on the socket.
const maxRequestBytes = 8 << 20

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
	listFn func(ctx context.Context, n nftnames.Names) ([]setElem, error)

	// nowFn is the clock behind cache-expiry decisions (defaults to
	// time.Now). Injectable so tests can drive an entry past its kernel
	// timeout without sleeping.
	nowFn func() time.Time

	// mutateMu serializes every blocked-set MUTATION (add/del/flush) across
	// its full span — the nft kernel exec AND the follow-up s.blocked cache
	// write together, as one atomic unit (issue #418). Without it, the kernel
	// write (which holds no lock) and the cache write (a brief s.mu section)
	// are two separate steps, so a re-ban `add` and a stale post-expire `del`
	// for the SAME address arriving on concurrent connections (pipeline Ban
	// vs expiry-tick / probe Sync in the daemon) can have their kernel-effect
	// order differ from their cache-effect order. That leaves kernel=absent /
	// cache=present: `list` then reports the ban as enforced, Sync trusts
	// `list` and never re-adds it, and the ban leaks until the helper
	// restarts (the sustained ban_ineffective signature of #418/#383).
	// mutateMu is the OUTER lock (held across the exec); s.mu stays the INNER
	// lock guarding the map itself, so `list`/`switchNames` readers are never
	// blocked for a whole nft exec, only for the brief map access.
	mutateMu sync.Mutex

	// blocked maps each canonical IP/CIDR string in the nft set to its
	// expiry deadline; the zero Time means permanent. The deadline mirrors
	// nft's per-element `timeout`, which the KERNEL enforces on its own —
	// so `list` must treat entries past their deadline as gone even though
	// no del verb ever removed them. A plain presence map here is how a
	// permanently-banned IP went unenforced for 12+ days on the dogfooding
	// host: the kernel expired the old timed element, the cache kept
	// claiming it was present, and every Sync skipped the re-add (#383).
	mu      sync.RWMutex
	blocked map[string]time.Time

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
		nowFn:      time.Now,
		blocked:    make(map[string]time.Time),
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
	els, err := s.listFn(ctx, s.names)
	if err != nil {
		return fmt.Errorf("enforcer: load existing set state: %w", err)
	}
	s.mu.Lock()
	for _, el := range els {
		s.blocked[el.ip] = s.deadline(el.ttl)
	}
	s.mu.Unlock()
	slog.Info("enforcer: nft table ready", "existing_entries", len(els))
	return nil
}

// deadline converts a remaining lifetime into a cache deadline; 0 (permanent)
// maps to the zero Time.
func (s *Server) deadline(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return s.nowFn().Add(ttl)
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
	// feeds_sync requests carry a full desired-state batch — raise the line
	// cap above the Scanner default (64KiB) while keeping a hard bound.
	sc.Buffer(make([]byte, 64*1024), maxRequestBytes)
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
		return enforce.Response{OK: true, Features: []string{
			enforce.FeatureCustomNames, enforce.FeatureFeedsSync,
		}}

	case "feeds_sync":
		// Full desired-state replace of the reputation-feed sets (issue
		// #195). Every element is re-validated in THIS process (§3) and
		// must carry a positive TTL — feed entries are never permanent.
		// The cap is a hard reject, not a truncation: silently dropping
		// entries the daemon thinks are applied would be a lie.
		if len(req.Elements) > enforce.MaxFeedElements {
			return enforce.Response{OK: false, Error: fmt.Sprintf(
				"feeds_sync: %d elements exceeds the %d cap", len(req.Elements), enforce.MaxFeedElements)}
		}
		for _, e := range req.Elements {
			if err := validateIP(e.IP); err != nil {
				return enforce.Response{OK: false, Error: fmt.Sprintf("feeds_sync: %v", err)}
			}
			if e.TTLSeconds <= 0 {
				return enforce.Response{OK: false, Error: fmt.Sprintf(
					"feeds_sync: element %s: ttl must be positive (feed entries are never permanent)", e.IP)}
			}
		}
		// The feed sets are separate from the ban sets and cache, but the
		// mutation still serializes with other nft writes.
		s.mutateMu.Lock()
		defer s.mutateMu.Unlock()
		if err := nftFeedsSync(ctx, s.run, names, req.Elements); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		return enforce.Response{OK: true}

	case "netcheck":
		// Functional netlink probe (issue #213): one read-only `nft list set`
		// executed INSIDE this sandboxed process proves the unit still grants
		// what enforcement depends on (AF_NETLINK in RestrictAddressFamilies,
		// CAP_NET_ADMIN) — testing effect, not unit-file text. "ping" cannot
		// stand in for this: it never touches netlink. No arguments, no
		// mutation, no cache access.
		if _, err := s.listFn(ctx, names); err != nil {
			return enforce.Response{OK: false, Error: "netlink probe failed: " + err.Error()}
		}
		return enforce.Response{OK: true}

	case "list":
		// Entries past their deadline were already removed by the KERNEL's
		// per-element timeout — reporting them would make Sync skip re-adds
		// against an empty kernel set (the 12-day silent ban leak of #383).
		now := s.nowFn()
		s.mu.RLock()
		ips := make([]string, 0, len(s.blocked))
		var stale []string
		for ip, dl := range s.blocked {
			if !dl.IsZero() && now.After(dl) {
				stale = append(stale, ip)
				continue
			}
			ips = append(ips, ip)
		}
		s.mu.RUnlock()
		if len(stale) > 0 {
			// Lazy prune, re-checked under the write lock: a concurrent
			// re-add may have refreshed the deadline since the read pass.
			s.mu.Lock()
			for _, ip := range stale {
				if dl, ok := s.blocked[ip]; ok && !dl.IsZero() && now.After(dl) {
					delete(s.blocked, ip)
				}
			}
			s.mu.Unlock()
		}
		return enforce.Response{OK: true, IPs: ips}

	case "flush":
		// Serialize the kernel flush + cache reset against concurrent add/del
		// so no mutation's cache write can land after the flush cleared the
		// map yet before its kernel effect (issue #418).
		s.mutateMu.Lock()
		defer s.mutateMu.Unlock()
		if err := nftFlush(ctx, s.run, names); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		s.mu.Lock()
		s.blocked = make(map[string]time.Time)
		s.mu.Unlock()
		return enforce.Response{OK: true}

	case "add":
		if err := validateIP(req.IP); err != nil {
			return enforce.Response{OK: false, Error: err.Error()}
		}
		// Hold mutateMu across BOTH the kernel add and the cache write so a
		// concurrent del for the same IP cannot interleave between them and
		// desync the cache from the kernel (issue #418). See the mutateMu
		// field comment for the leak this prevents. Released before the ss
		// teardown below, which touches neither the kernel set nor the cache.
		s.mutateMu.Lock()
		// Re-adding an element that is still in the kernel does NOT replace
		// its `timeout` — nft keeps the old timer (auto-merge). A strike
		// upgrade (24h → 7d → permanent) would silently retain the shorter
		// expiry: on the dogfooding host a permanent re-ban kept a dying
		// timer and the IP went unenforced for 12+ days (issue #383). When
		// the cache says the element exists, delete it first so the add
		// installs the new TTL. The element being already gone (kernel timer
		// fired) is fine; any other delete failure would make the add
		// meaningless, so it surfaces. The microseconds-wide unprotected
		// window between del and add is held under mutateMu and is strictly
		// safer than a ban running on the wrong, shorter timer.
		s.mu.RLock()
		oldDeadline, present := s.blocked[req.IP]
		s.mu.RUnlock()
		deleted := false
		if present {
			if err := nftDel(ctx, s.run, names, req.IP); err != nil && !errors.Is(err, errElementAbsent) {
				s.mutateMu.Unlock()
				return enforce.Response{OK: false, Error: err.Error()}
			}
			deleted = true
		}
		if err := nftAdd(ctx, s.run, names, req.IP, req.TTLSeconds); err != nil {
			// Watchdog for the interrupted replace (issue #214): the delete
			// half landed but the add failed — without recovery the kernel
			// would silently hold LESS than either the old or the new state.
			// Best-effort rollback: restore the previous element with its
			// remaining lifetime; if even that fails, make the cache agree
			// with the (empty) kernel so the daemon's next reconcile re-adds
			// from the store instead of trusting a ghost.
			if deleted {
				restoreTTL := int64(0) // zero deadline = permanent
				if !oldDeadline.IsZero() {
					rem := time.Until(oldDeadline)
					if rem < time.Second {
						rem = time.Second
					}
					restoreTTL = int64(rem / time.Second)
				}
				if rerr := nftAdd(ctx, s.run, names, req.IP, restoreTTL); rerr != nil {
					s.mu.Lock()
					delete(s.blocked, req.IP)
					s.mu.Unlock()
					slog.ErrorContext(ctx, "enforcer: replace interrupted and rollback failed — element dropped; daemon reconcile will re-add from the store",
						"ip", req.IP, "add_err", err.Error(), "rollback_err", rerr.Error())
				} else {
					slog.WarnContext(ctx, "enforcer: replace interrupted — previous element restored with its remaining lifetime",
						"ip", req.IP, "add_err", err.Error())
				}
			}
			s.mutateMu.Unlock()
			return enforce.Response{OK: false, Error: err.Error()}
		}
		s.mu.Lock()
		s.blocked[req.IP] = s.deadline(time.Duration(req.TTLSeconds) * time.Second)
		s.mu.Unlock()
		s.mutateMu.Unlock()
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
		// Serialize the kernel delete + cache write against a concurrent add
		// for the same IP so the two mutations' kernel order and cache order
		// can never diverge (issue #418).
		s.mutateMu.Lock()
		defer s.mutateMu.Unlock()
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
	els, err := s.listFn(ctx, want)
	if err != nil {
		return fmt.Errorf("enforcer: load state from table %q: %w", want.Table, err)
	}
	s.blocked = make(map[string]time.Time, len(els))
	for _, el := range els {
		s.blocked[el.ip] = s.deadline(el.ttl)
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
		"table", want.Table, "set", want.Set4, "existing_entries", len(els))
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
