// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/evertramos/ezy-shield/internal/cdndetect"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/internal/ownership"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// asnString formats a uint32 ASN as "AS<n>", or "" when zero.
func asnString(n uint32) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("AS%d", n)
}

const (
	// socketPerm is the permission bits for the control socket (owner+group rw).
	socketPerm = 0o660
	// connDeadline is the read/write deadline per connection.
	connDeadline = 10 * time.Second
	// roSocketName is the read-only companion socket (issue #212), created
	// next to the primary socket and group-owned by ownership.ViewGroup.
	roSocketName = "ezyshield-ro.sock"
)

// ROSocketPath returns the read-only socket path for a given primary control
// socket path: the same directory, fixed name roSocketName.
func ROSocketPath(socketPath string) string {
	return filepath.Join(filepath.Dir(socketPath), roSocketName)
}

// readOnlyVerbs is the CLOSED allowlist of verbs served on the read-only
// socket (issue #212). Everything else — including verbs added in the
// future — is denied there by default: a new verb only becomes visible to
// the viewer tier by being added here deliberately.
var readOnlyVerbs = map[string]bool{
	"status":       true,
	"list":         true,
	"list_allow":   true,
	"events":       true,
	"report":       true,
	"subscribe":    true,
	"metrics":      true,
	"feeds_status": true,
}

// mutatingVerbs lists every known verb with write authority; each request
// for one is recorded in the append-only audit journal with the requesting
// peer credential (SO_PEERCRED), successful or not.
var mutatingVerbs = map[string]bool{
	"arm":           true,
	"arm_keep":      true,
	"disarm":        true,
	"ban":           true,
	"unban":         true,
	"allow":         true,
	"unallow":       true,
	"feeds_refresh": true,
	"disable_all":   true,
	"prune":         true,
}

// ErrSocketInUse is returned by ProbeSocket when another daemon is already
// listening on the control socket. Daemon.Run surfaces this before starting so
// a manual `ezyshield watch` doesn't clobber a systemd-managed daemon's socket
// (issue #14). Callers should treat this as a startup failure, not warn-and-go.
var ErrSocketInUse = errors.New("another ezyshield daemon is already listening on this socket")

// ProbeSocket returns nil if socketPath is safe to bind (missing, or present
// but stale — no listener). Returns ErrSocketInUse if a live daemon is
// listening. Called from Daemon.Run before starting so we fail fast instead of
// unlinking a live socket. Uses a short dial timeout so a busy but responsive
// daemon still answers.
//
// Safety: if the path exists but isn't a unix socket (regular file, symlink,
// dir), or if we can't determine whether it's live (permission denied on
// stat/dial), we treat that as "in use" — os.Remove on an unknown file would
// be data loss. Only a clean "socket file present, dial refused" counts as
// stale.
func ProbeSocket(ctx context.Context, socketPath string) error {
	info, err := os.Stat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		// Permission denied, ENOTDIR, or anything else — don't touch it.
		return fmt.Errorf("%w (stat %s): %w", ErrSocketInUse, socketPath, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%w: %s exists but is not a unix socket (mode=%s) — refusing to remove", ErrSocketInUse, socketPath, info.Mode())
	}
	d := net.Dialer{Timeout: 200 * time.Millisecond}
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("%w: %s", ErrSocketInUse, socketPath)
	}
	// A "connection refused" on a real unix socket file means no listener —
	// safe to treat as stale. Any other dial error (permission denied,
	// timeout on a slow-but-live daemon) should be treated as in-use, since
	// silently removing could clobber a live socket we simply can't reach.
	//
	// ENOENT means the file was removed between our Stat and Dial (a crashed
	// daemon cleaning up, or another restart racing us). Treat it the same as
	// "path didn't exist to begin with" — safe to bind. Otherwise a benign
	// race would surface as a spurious startup failure.
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("%w (dial %s): %w", ErrSocketInUse, socketPath, err)
}

// serveSocket creates the unix socket and accepts connections until ctx is done.
// It creates the socket directory (0750) if absent.
//
// Security: the socket is created at socketPath with mode 0660. The kernel
// enforces access by UID/GID; no further authentication is done. All mutating
// commands (ban, unban, allow) are written to audit_log.
//
// Callers MUST run ProbeSocket first (see Daemon.Run) to avoid clobbering a
// live daemon's socket — issue #14. The os.Remove below is intended only for
// stale sockets from previous runs, which ProbeSocket has already confirmed.
func (d *Daemon) serveSocket(ctx context.Context) {
	dir := filepath.Dir(d.socketPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		slog.ErrorContext(ctx, "daemon: socket dir create failed",
			"dir", dir, "err", err)
		return
	}

	ln := d.bindControlSocket(ctx, d.socketPath, ownership.Group)
	if ln == nil {
		return
	}
	slog.InfoContext(ctx, "daemon: control socket listening", "path", d.socketPath)

	// Read-only companion socket (issue #212): same wire protocol, but only
	// the readOnlyVerbs allowlist is served. Group ezyshield-view + mode
	// 0660 means the kernel enforces WHO can connect; the verb allowlist
	// enforces WHAT they can do. A bind failure here degrades to
	// primary-socket-only operation — never a daemon startup failure.
	roPath := ROSocketPath(d.socketPath)
	if roPath != d.socketPath {
		if roLn := d.bindControlSocket(ctx, roPath, ownership.ViewGroup); roLn != nil {
			slog.InfoContext(ctx, "daemon: read-only control socket listening",
				"path", roPath, "group", ownership.ViewGroup)
			go d.acceptLoop(ctx, roLn, true)
		}
	}

	d.acceptLoop(ctx, ln, false)
}

// bindControlSocket binds one unix control socket at path with the shared
// permission model (group-owned, mode 0660). Returns nil on failure (logged).
func (d *Daemon) bindControlSocket(ctx context.Context, path, group string) net.Listener {
	// Remove a stale socket from a previous run — ProbeSocket in Run has
	// already confirmed no live daemon owns the primary socket (and the RO
	// socket is only ever bound by the daemon that owns the primary).
	_ = os.Remove(path)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		slog.ErrorContext(ctx, "daemon: socket listen failed",
			"path", path, "err", err)
		return nil
	}

	// Set permissions immediately after bind so a window between bind and chmod
	// is as narrow as possible. The standard for security daemons (fail2ban,
	// sshguard) is group ownership + 0660 so members can use the socket
	// without sudo — see issues #6 and #212. When the group does not exist
	// the socket stays root-owned 0660: fail closed, root-only access.
	if err := ownership.ChownToGroup(path, group); err != nil {
		slog.WarnContext(ctx, "daemon: could not set control socket group; only root can use it until the group exists",
			"path", path, "group", group, "err", err)
	}
	if err := os.Chmod(path, socketPerm); err != nil {
		slog.WarnContext(ctx, "daemon: socket chmod failed",
			"path", path, "err", err)
	}

	// Close the listener when the context is cancelled so Accept unblocks.
	// The ListenConfig.Listen call already wires ctx cancellation to ln.Close()
	// for the common case, but we add explicit cleanup for safety.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	return ln
}

// acceptLoop serves one listener until ctx is done. readOnly marks every
// connection from this listener as viewer-tier.
func (d *Daemon) acceptLoop(ctx context.Context, ln net.Listener, readOnly bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // expected: context cancelled
			}
			slog.ErrorContext(ctx, "daemon: socket accept error", "err", err)
			continue
		}
		go d.handleConnScoped(ctx, conn, readOnly)
	}
}

// handleConn is the full-access entry point (primary socket and tests).
func (d *Daemon) handleConn(ctx context.Context, conn net.Conn) {
	d.handleConnScoped(ctx, conn, false)
}

// handleConnScoped decodes one SocketRequest, enforces the connection's
// access tier, dispatches it, and encodes the response. Mutating verbs are
// recorded in the append-only audit journal with the requesting peer
// credential (SO_PEERCRED) — successful or not.
func (d *Daemon) handleConnScoped(ctx context.Context, conn net.Conn, readOnly bool) {
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(connDeadline)
	_ = conn.SetDeadline(deadline)

	var req SocketRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeResponse(conn, SocketResponse{Error: fmt.Sprintf("decode request: %v", err)})
		return
	}

	// Deny by default on the read-only tier: only the closed readOnlyVerbs
	// allowlist passes; every other verb — mutating, unknown, or future —
	// requires the operator socket.
	if readOnly && !readOnlyVerbs[req.Verb] {
		uid, gid, credOK := peerCredOf(conn)
		slog.WarnContext(ctx, "daemon: read-only socket refused verb",
			"verb", req.Verb, "peer_uid", uid, "peer_gid", gid, "peer_known", credOK)
		// A viewer attempting a write verb is a security-relevant event:
		// journal the refusal with the peer credential.
		if mutatingVerbs[req.Verb] {
			d.auditSocketCmd(ctx, conn, req, false)
		}
		writeResponse(conn, SocketResponse{Error: fmt.Sprintf(
			"read-only socket: verb %q requires the operator socket (group %s)",
			req.Verb, ownership.Group)})
		return
	}

	var resp SocketResponse
	switch req.Verb {
	case "status":
		resp = d.handleStatus(ctx)
	case "list":
		resp = d.handleList(ctx)
	case "list_allow":
		resp = d.handleListAllow(ctx)
	case "events":
		resp = d.handleEvents(ctx, req)
	case "report":
		resp = d.handleReport(ctx, req)
	case "subscribe":
		// Long-lived, read-only event stream; writes its own ack + events.
		d.handleSubscribe(ctx, conn)
		return
	case "arm":
		resp = d.handleArm(ctx, req)
	case "arm_keep":
		resp = d.handleArmKeep(ctx)
	case "disarm":
		resp = d.handleDisarm(ctx)
	case "ban":
		resp = d.handleBan(ctx, req)
	case "unban":
		resp = d.handleUnban(ctx, req)
	case "allow":
		resp = d.handleAllow(ctx, req)
	case "unallow":
		resp = d.handleUnallow(ctx, req)
	case "metrics":
		resp = d.handleMetrics(ctx)
	case "feeds_status":
		resp = d.handleFeedsStatus(ctx)
	case "feeds_refresh":
		resp = d.handleFeedsRefresh(ctx, req)
	case "disable_all":
		resp = d.handleDisableAll(ctx)
	case "prune":
		resp = d.handlePrune(ctx, req)
	default:
		resp = SocketResponse{Error: fmt.Sprintf("unknown verb %q; valid: status list list_allow events subscribe report arm arm_keep disarm ban unban allow unallow disable_all prune feeds_status feeds_refresh metrics", req.Verb)}
	}

	// Audit attribution (issue #212): every mutating verb request — refused
	// ones included — lands in the append-only journal with the peer
	// credential, so "who disarmed / who unbanned" is always answerable.
	if mutatingVerbs[req.Verb] {
		d.auditSocketCmd(ctx, conn, req, resp.Error == "")
	}

	writeResponse(conn, resp)
}

// auditSocketCmd appends one audit entry for a mutating socket request.
// The target is length-capped; renderers sanitize on display like every
// other audit reason.
func (d *Daemon) auditSocketCmd(ctx context.Context, conn net.Conn, req SocketRequest, ok bool) {
	uid, gid, credOK := peerCredOf(conn)
	peer := "peer=unknown"
	if credOK {
		peer = fmt.Sprintf("peer_uid=%d peer_gid=%d", uid, gid)
	}
	target := req.IP
	if len(target) > 64 {
		target = target[:64]
	}
	reason := fmt.Sprintf("verb=%s ok=%t %s", req.Verb, ok, peer)
	if target != "" {
		reason = fmt.Sprintf("verb=%s target=%s ok=%t %s", req.Verb, target, ok, peer)
	}
	if err := d.store.AuditSystem(ctx, "socket_cmd", reason); err != nil {
		slog.ErrorContext(ctx, "daemon: audit socket_cmd failed", "verb", req.Verb, "err", err)
	}
}

// subscribeWriteTimeout bounds each event write to a subscriber so a stuck
// client is dropped instead of pinning the connection goroutine forever.
const subscribeWriteTimeout = 5 * time.Second

// handleSubscribe streams live StreamEvents to conn until the client
// disconnects or ctx is cancelled.
//
// Security (§6 control surfaces): this verb is strictly read-only — it never
// touches the store, the enforcer, or daemon state beyond registering an
// in-memory subscriber channel; any extra fields on the request are ignored.
// Event payloads may embed hostile log content; terminal clients must
// sanitize before rendering (see StreamEvent doc).
func (d *Daemon) handleSubscribe(ctx context.Context, conn net.Conn) {
	// handleConn set a short request/response deadline; a subscription is
	// long-lived, so clear it and bound individual writes instead.
	_ = conn.SetDeadline(time.Time{})

	if err := json.NewEncoder(conn).Encode(SocketResponse{OK: true}); err != nil {
		slog.Debug("daemon: subscribe ack write error", "err", err)
		return
	}

	ch := d.events.subscribe()
	defer d.events.unsubscribe(ch)

	slog.InfoContext(ctx, "daemon: event subscriber connected")
	defer slog.InfoContext(ctx, "daemon: event subscriber disconnected")

	// The client sends nothing after the request, so a Read unblocking means
	// it closed its end (or handleConn's deferred Close fired). This lets an
	// idle subscription be reaped promptly instead of waiting for the next
	// event write to fail.
	clientGone := make(chan struct{})
	go func() {
		defer close(clientGone)
		buf := make([]byte, 1)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()

	enc := json.NewEncoder(conn)
	for {
		select {
		case <-ctx.Done():
			return
		case <-clientGone:
			return
		case ev := <-ch:
			_ = conn.SetWriteDeadline(time.Now().Add(subscribeWriteTimeout))
			if err := enc.Encode(ev); err != nil {
				return
			}
			_ = conn.SetWriteDeadline(time.Time{})
		}
	}
}

// handleStatus returns daemon health and current ban count. Simulated
// dry-run bans are reported separately from enforced ones — status must
// never claim a simulated ban as active protection (ADR-0009 §5).
func (d *Daemon) handleStatus(ctx context.Context) SocketResponse {
	bans, err := d.store.ActiveBans(ctx)
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("active bans: %v", err)}
	}

	active, simulated := 0, 0
	for _, b := range bans {
		if b.Op == "dry_ban" {
			simulated++
		} else {
			active++
		}
	}

	enfState, enfDetail := d.enforcementState()
	collState, collDetail := d.collectorsState()
	// Shared-CDN-range guard health (issue #178): "unavailable" means bans
	// are proceeding WITHOUT the shared-range check — loud, never silent.
	cdnState := "ok"
	if _, err := cdndetect.SharedRanges(); err != nil {
		cdnState = "unavailable: " + err.Error()
	}
	data := StatusData{
		Uptime:            time.Since(d.startTime).Round(time.Second).String(),
		Armed:             d.policy.IsArmed(),
		EnforcementState:  string(enfState),
		EnforcementDetail: enfDetail,
		CollectorsState:   string(collState),
		CollectorsDetail:  collDetail,
		CDNRangesState:    cdnState,
		ActiveBans:        active,
		SimulatedBans:     simulated,
		ArmedUntil:        d.armedUntil(ctx),
		Version:           d.version,
	}
	raw, _ := json.Marshal(data)
	return SocketResponse{OK: true, Data: raw}
}

// handleList returns all active bans from the store, enriched with geo data
// when an enricher is configured.
func (d *Daemon) handleList(ctx context.Context) SocketResponse {
	bans, err := d.store.ActiveBans(ctx)
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("active bans: %v", err)}
	}

	entries := make([]BanEntry, 0, len(bans))
	for _, b := range bans {
		// "permanent" only for a genuine no-expiry ban. A remaining TTL of
		// zero means expired — the store skips those, but render honestly if
		// one ever slips through; never dress an expired ban as permanent
		// (issue #279).
		var ttl string
		switch {
		case b.Permanent:
			ttl = "permanent"
		case b.TTL > 0:
			ttl = b.TTL.Round(time.Second).String()
		default:
			ttl = "expired"
		}
		e := BanEntry{
			IP:        b.IP.String(),
			TTL:       ttl,
			Strike:    b.Strike,
			Reason:    b.Reason,
			Simulated: b.Op == "dry_ban",
		}
		if d.enricher != nil {
			enr := d.enricher.Lookup(b.IP)
			e.Country = enr.Country
			e.ASN = asnString(enr.ASN)
		}
		entries = append(entries, e)
	}
	raw, _ := json.Marshal(entries)
	return SocketResponse{OK: true, Data: raw}
}

// handleBan manually bans an IP or CIDR. It bypasses the rule engine's
// scoring, but NOT its safety guards: every manual ban passes the same
// allowlist / anti-lockout / rate-limit gate as automatic decisions
// (issue #211, decision.AuthorizeManualBan) plus the daemon's runtime
// allowlist. Refusals are audited (op "ban_refused") and returned to the
// CLI naming the guard that fired. The hard guards have no override —
// allowlist and anti-lockout are hard rules, the rate-limit knob is
// policy's max_bans_per_minute; only the CDN shared-range guard (issue
// #178) honors req.Force.
func (d *Daemon) handleBan(ctx context.Context, req SocketRequest) SocketResponse {
	prefix, err := parseSocketTarget(req.IP)
	if err != nil {
		return SocketResponse{Error: err.Error()}
	}

	var ttl time.Duration
	if req.TTL != "" {
		ttl, err = parseExtendedDuration(req.TTL)
		if err != nil {
			return SocketResponse{Error: fmt.Sprintf("invalid ttl %q: %v", req.TTL, err)}
		}
	}

	// ── Manual-ban guards (issue #211) ──────────────────────────────────
	// Runtime allowlist (operator 'allow' entries) first — it lives in the
	// daemon, outside the engine's static set.
	if hit, entry := d.runtimeAllowlistOverlap(prefix); hit {
		return d.refuseManualBan(ctx, prefix, ttl,
			fmt.Sprintf("target %s overlaps runtime allowlist entry %s", prefix, entry))
	}
	// Engine guards: static allowlist/admin_cidrs, SSH-peer anti-lockout
	// (daemon env + the CLI's own forwarded peer), shared ban rate limit.
	var peers []netip.Addr
	if p, perr := netip.ParseAddr(strings.TrimSpace(req.Peer)); perr == nil {
		peers = append(peers, p)
	}
	if err := d.decEng.AuthorizeManualBan(ctx, prefix, req.Force, peers...); err != nil {
		return d.refuseManualBan(ctx, prefix, ttl, err.Error())
	}

	if d.enforcer != nil && d.policy.IsArmed() {
		t := targetFromPrefix(prefix, ttl)
		if err := d.enforcer.Ban(ctx, t); err != nil {
			return SocketResponse{Error: fmt.Sprintf("enforcer ban: %v", err)}
		}
	}

	op := "ban"
	if !d.policy.IsArmed() {
		op = "dry_ban"
	}

	reason := req.Reason
	if reason == "" {
		reason = "manual ban via CLI"
	}

	// For a single-IP ban, record in bans_active so `ezyshield list` sees it.
	// AuditOp alone (the previous behaviour) only wrote to audit_log, which
	// meant a manual ban reached nftables but silently didn't show up in list.
	// bans_active is keyed by single IP; a CIDR ban still only gets audited
	// (the store doesn't model prefix bans yet).
	//
	// Fail-safe: if the atomic RecordManualBan transaction fails (schema
	// mismatch, disk full), fall back to AuditOp so the operator action is at
	// least journaled — losing both the bans_active row and the audit trail
	// would be a silent-failure regression (§10 SECURITY-REVIEW).
	//
	// stored tracks whether the primary store write (RecordManualBan or AuditOp)
	// succeeded. We only emit the "daemon: action" INFO line on that happy path:
	// the audit-fallback ERROR-log branch already surfaces the failure, and a
	// duplicate INFO there would falsely suggest the action was recorded.
	// Recorded regardless of armed state: a manual ban while disarmed is a
	// dry_ban ROW (dry_run=1), so `list` and the status SimulatedBans count
	// mirror it exactly like pipeline dry_bans — audit-only recording made
	// the operator's own action invisible in dry-run mode (issue #358,
	// ADR-0009 §5 "dry-run mirrors armed").
	stored := false
	if prefix.Bits() == prefix.Addr().BitLen() {
		if err := d.store.RecordManualBan(ctx, prefix.Addr(), ttl, reason, !d.policy.IsArmed()); err != nil {
			slog.ErrorContext(ctx, "daemon: record manual ban failed, falling back to audit-only",
				"ip", prefix.Addr(), "err", err)
			if auditErr := d.store.AuditOp(ctx, op, prefix, ttl, reason); auditErr != nil {
				slog.ErrorContext(ctx, "daemon: audit fallback also failed",
					"prefix", prefix, "err", auditErr)
			}
		} else {
			stored = true
		}
	} else if err := d.store.AuditOp(ctx, op, prefix, ttl, reason); err != nil {
		slog.ErrorContext(ctx, "daemon: audit manual ban", "prefix", prefix, "err", err)
	} else {
		stored = true
	}

	// Emit an INFO line matching the pipeline path's message so tools that grep
	// "daemon: action" catch CLI actions too. source=cli discriminates from the
	// automatic path (which sets source=rules|ai inside reason today). Issue #45.
	if stored {
		slog.InfoContext(ctx, "daemon: action",
			"op", op,
			"ip", prefix.String(),
			"ttl", ttl,
			"reason", reason,
			"source", "cli",
		)
	}

	d.publishActionEvent(op, prefixDisplay(prefix), 0, ttl, reason, "cli")

	return SocketResponse{OK: true}
}

// refuseManualBan audits and reports a manual ban blocked by a safety
// guard (issue #211). The refusal is recorded in the append-only audit_log
// (op "ban_refused", reason names the guard) and published on the event
// stream, then returned as a clear error to the CLI.
func (d *Daemon) refuseManualBan(ctx context.Context, prefix netip.Prefix, ttl time.Duration, reason string) SocketResponse {
	slog.WarnContext(ctx, "daemon: manual ban refused", "prefix", prefix, "reason", reason)
	if err := d.store.AuditOp(ctx, "ban_refused", prefix, ttl, reason); err != nil {
		slog.ErrorContext(ctx, "daemon: audit ban_refused", "prefix", prefix, "err", err)
	}
	d.publishActionEvent("ban_refused", prefixDisplay(prefix), 0, ttl, reason, "cli")
	return SocketResponse{Error: "refusing manual ban: " + reason}
}

// handleUnban removes a single IP or every IP within a CIDR from the ban set
// (in the store) and asks the enforcer to drop the matching rule(s).
func (d *Daemon) handleUnban(ctx context.Context, req SocketRequest) SocketResponse {
	prefix, err := parseSocketTarget(req.IP)
	if err != nil {
		return SocketResponse{Error: err.Error()}
	}

	if d.enforcer != nil {
		t := targetFromPrefix(prefix, 0)
		if err := d.enforcer.Unban(ctx, t); err != nil {
			// Log but don't fail — store cleanup should still proceed.
			slog.ErrorContext(ctx, "daemon: enforcer unban failed", "prefix", prefix, "err", err)
		}
	}

	if prefix.Bits() == prefix.Addr().BitLen() {
		if err := d.store.Unban(ctx, prefix.Addr()); err != nil {
			return SocketResponse{Error: fmt.Sprintf("store unban: %v", err)}
		}
	} else {
		if _, err := d.store.UnbanPrefix(ctx, prefix); err != nil {
			return SocketResponse{Error: fmt.Sprintf("store unban prefix: %v", err)}
		}
	}

	// Emit an INFO line matching the pipeline path's message so tools that grep
	// "daemon: action" catch CLI unbans too. Reason is empty because the CLI
	// unban path doesn't send one today — issue #45 said to leave that as-is
	// rather than invent a placeholder.
	slog.InfoContext(ctx, "daemon: action",
		"op", "unban",
		"ip", prefix.String(),
		"ttl", time.Duration(0),
		"reason", req.Reason,
		"source", "cli",
	)

	d.publishActionEvent("unban", prefixDisplay(prefix), 0, 0, req.Reason, "cli")

	return SocketResponse{OK: true}
}

// handleAllow persists prefix to the allowlist (with an optional TTL) and
// updates the daemon's in-memory runtime allowlist so the change takes effect
// immediately for the pipeline.
func (d *Daemon) handleAllow(ctx context.Context, req SocketRequest) SocketResponse {
	prefix, err := parseSocketTarget(req.IP)
	if err != nil {
		return SocketResponse{Error: err.Error()}
	}
	prefix = prefix.Masked()

	if req.For != "" && req.Until != "" {
		return SocketResponse{Error: "cannot combine 'for' and 'until'"}
	}

	var expiresAt *time.Time
	switch {
	case req.For != "":
		dur, err := parseExtendedDuration(req.For)
		if err != nil {
			return SocketResponse{Error: fmt.Sprintf("invalid duration %q: %v", req.For, err)}
		}
		if dur <= 0 {
			return SocketResponse{Error: fmt.Sprintf("duration must be positive: %q", req.For)}
		}
		t := time.Now().UTC().Add(dur)
		expiresAt = &t
	case req.Until != "":
		t, err := parseUntil(req.Until)
		if err != nil {
			return SocketResponse{Error: fmt.Sprintf("invalid until %q: %v", req.Until, err)}
		}
		if !t.After(time.Now()) {
			return SocketResponse{Error: fmt.Sprintf("until is in the past: %q", req.Until)}
		}
		expiresAt = &t
	}

	if err := d.store.AddAllow(ctx, prefix, expiresAt, req.Reason); err != nil {
		return SocketResponse{Error: fmt.Sprintf("store add allow: %v", err)}
	}

	var ttl time.Duration
	if expiresAt != nil {
		ttl = time.Until(*expiresAt)
	}
	if err := d.store.AuditOp(ctx, "allow", prefix, ttl, req.Reason); err != nil {
		slog.ErrorContext(ctx, "daemon: audit allow", "prefix", prefix, "err", err)
	}

	if err := d.reloadAllowlist(ctx); err != nil {
		slog.ErrorContext(ctx, "daemon: reload allowlist after add", "err", err)
	}

	// Push the new entry to the enforcer's @allowed set so the anti-lockout
	// invariant (AGENTS.md §2) holds at the raw/prerouting hook too — where
	// the block drops happen (issue #23). Only enforcers that manage local
	// firewall state care about this; edge enforcers (Cloudflare) don't need
	// it. Uses a type assertion so the sdk.Enforcer interface stays minimal.
	// Failure is not fatal: the daemon-level allowlist check still catches
	// the target upstream, and SyncAllowlist on the next startup reconciles.
	if syncer, ok := d.enforcer.(allowlistSyncer); ok {
		if err := syncer.Allow(ctx, prefix); err != nil {
			slog.ErrorContext(ctx, "daemon: enforcer allow failed",
				"prefix", prefix, "err", err)
		}
	}

	slog.InfoContext(ctx, "daemon: runtime allowlist updated",
		"prefix", prefix, "expires_at", expiresAt, "reason", req.Reason)

	// Emit an INFO line matching the pipeline path's message so tools that grep
	// "daemon: action" catch CLI allows too. ttl mirrors the value we hand to
	// AuditOp above (0 for permanent, otherwise the computed remaining
	// duration), so this line and the audit_log entry agree. Issue #45.
	slog.InfoContext(ctx, "daemon: action",
		"op", "allow",
		"ip", prefix.String(),
		"ttl", ttl,
		"reason", req.Reason,
		"source", "cli",
	)

	d.publishActionEvent("allow", prefixDisplay(prefix), 0, ttl, req.Reason, "cli")

	return SocketResponse{OK: true}
}

// handleUnallow removes prefix from the persistent runtime allowlist,
// refreshes the daemon's in-memory allowlist, and drops the entry from the
// enforcer's @allowed set (issue #330). This does not weaken Hard Rule 1 —
// "allowlist always wins" applies to entries that exist; removal is the
// explicit operator action the allow help text promises ("permanent until
// explicitly removed"). Only store-owned runtime entries are removable:
// config-file allowlist entries survive reloadAllowlist untouched.
func (d *Daemon) handleUnallow(ctx context.Context, req SocketRequest) SocketResponse {
	prefix, err := parseSocketTarget(req.IP)
	if err != nil {
		return SocketResponse{Error: err.Error()}
	}
	prefix = prefix.Masked()

	removed, err := d.store.RemoveAllow(ctx, prefix)
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("store remove allow: %v", err)}
	}
	if removed == 0 {
		return SocketResponse{Error: fmt.Sprintf("%s is not in the runtime allowlist (the target must match the stored entry exactly; config-file entries cannot be removed at runtime)", prefixDisplay(prefix))}
	}

	if err := d.store.AuditOp(ctx, "unallow", prefix, 0, req.Reason); err != nil {
		slog.ErrorContext(ctx, "daemon: audit unallow", "prefix", prefix, "err", err)
	}

	if err := d.reloadAllowlist(ctx); err != nil {
		slog.ErrorContext(ctx, "daemon: reload allowlist after remove", "err", err)
	}

	// Mirror of the handleAllow push, but as a full re-sync: recompute the
	// exact static ∪ runtime union and push it via SyncAllowlist — the same
	// primitive the startup path and the expiry sweep use. A targeted
	// syncer.Unallow(prefix) guarded by an Overlaps check was wrong for the
	// containment case (issue #404, review of PR #398): a static /32 inside a
	// runtime-allowed /24 made the guard skip the removal, leaving the whole
	// /24 in @allowed until restart. Re-syncing keeps every prefix the static
	// policy (policy.Allowlist / admin_cidrs) still requires — anti-lockout,
	// Hard Rule 1 — while dropping exactly what nothing requires any more.
	// Failure is not fatal for the same reason as in handleAllow: a stale
	// extra @allowed entry only over-protects until the next reconcile.
	if err := d.syncEnforcerAllowlist(ctx); err != nil {
		slog.ErrorContext(ctx, "daemon: enforcer allowlist re-sync after unallow failed",
			"prefix", prefix, "err", err)
	}

	slog.InfoContext(ctx, "daemon: runtime allowlist updated",
		"prefix", prefix, "removed", removed, "reason", req.Reason)

	slog.InfoContext(ctx, "daemon: action",
		"op", "unallow",
		"ip", prefix.String(),
		"ttl", time.Duration(0),
		"reason", req.Reason,
		"source", "cli",
	)

	d.publishActionEvent("unallow", prefixDisplay(prefix), 0, 0, req.Reason, "cli")

	return SocketResponse{OK: true}
}

// handleEvents returns the last N audit_log rows in reverse chronological
// order. It is read-only; the append-only invariant on audit_log is
// unaffected. Limit defaults to 100 and is capped at 1000 by the store.
func (d *Daemon) handleEvents(ctx context.Context, req SocketRequest) SocketResponse {
	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	var (
		rows []store.AuditEntry
		err  error
	)
	if req.IP != "" {
		// --ip filter: exact-match a single address. AuditLogForIP matches the
		// ip column literally, so only a bare address is meaningful here — rows
		// recorded against a CIDR prefix target a range, not one host.
		addr, perr := netip.ParseAddr(req.IP)
		if perr != nil {
			return SocketResponse{Error: fmt.Sprintf("events: invalid ip %q: expected a bare address", req.IP)}
		}
		addr = addr.Unmap()
		rows, err = d.store.AuditLogForIP(ctx, addr, limit)
	} else {
		rows, err = d.store.ListAuditLog(ctx, limit)
	}
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("list audit_log: %v", err)}
	}
	out := make([]EventEntry, 0, len(rows))
	for _, e := range rows {
		out = append(out, EventEntry{
			ID:         e.ID,
			RecordedAt: e.RecordedAt,
			Op:         e.Op,
			IP:         e.IP,
			TTLSeconds: e.TTLSeconds,
			Strike:     e.Strike,
			Reason:     e.Reason,
		})
	}
	raw, _ := json.Marshal(out)
	return SocketResponse{OK: true, Data: raw}
}

// handleListAllow returns every persisted allowlist entry with display-ready
// expiry strings ("never", "<n>h remaining", or an ISO 8601 timestamp).
func (d *Daemon) handleListAllow(ctx context.Context) SocketResponse {
	entries, err := d.store.ListAllow(ctx)
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("list allow: %v", err)}
	}

	now := time.Now()
	out := make([]AllowEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, AllowEntry{
			Prefix:  e.Prefix.String(),
			Expires: formatExpires(e.ExpiresAt, now),
			Reason:  e.Reason,
		})
	}
	raw, _ := json.Marshal(out)
	return SocketResponse{OK: true, Data: raw}
}

// formatExpires renders an expiry time for `ezyshield list --allow` output.
// The zero time means permanent; a non-zero time within ~24 h is rendered as
// "<n>h remaining"; otherwise the absolute date is returned (RFC 3339 date).
func formatExpires(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	remaining := t.Sub(now)
	if remaining <= 0 {
		return "expired"
	}
	if remaining < 24*time.Hour {
		return remaining.Round(time.Hour).String() + " remaining"
	}
	return t.UTC().Format("2006-01-02")
}

// parseSocketTarget accepts a bare IP ("1.2.3.4") or a CIDR ("10.0.0.0/8")
// and returns the equivalent netip.Prefix (single hosts become /32 or /128).
//
// IPv4-mapped IPv6 spellings ("::ffff:a.b.c.d") that operators copy from
// dual-stack logs are canonicalized to plain IPv4 here, at the input
// boundary, so every downstream consumer sees one identity per address:
// the runtime-allowlist overlap check in handleBan (which runs before the
// engine's guards and would otherwise miss the mapped spelling of a
// protected IP), store keys, enforcer targets, and the matching
// unban/allow spellings (issue #314, PR #364 review). Mapped super-prefixes
// broader than /96 have no IPv4 equivalent and are rejected.
func parseSocketTarget(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("ip or cidr is required")
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return decision.NormalizePrefix(p)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid ip or cidr %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// targetFromPrefix maps a netip.Prefix to the sdk.Target shape expected by
// enforcers. Single-host prefixes go in the IP field so single-IP enforcers
// take the IP fast path; wider ranges go in Prefix.
func targetFromPrefix(p netip.Prefix, ttl time.Duration) sdk.Target {
	if p.Bits() == p.Addr().BitLen() {
		return sdk.Target{IP: p.Addr(), TTL: ttl}
	}
	return sdk.Target{Prefix: p, TTL: ttl}
}

// parseExtendedDuration extends time.ParseDuration with day units (e.g. "7d"
// or "30d") because Go's stdlib stops at hours. The trailing 'd' is converted
// to N*24h and then handed to time.ParseDuration; everything else is left as-is.
func parseExtendedDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid day count in %q", s)
		}
		if n < 0 {
			return 0, fmt.Errorf("negative day count in %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// parseUntil accepts ISO 8601 date or datetime in either local or UTC form.
// Date-only inputs are interpreted as 00:00 UTC on that date.
func parseUntil(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("expected ISO 8601 date or datetime")
}

// writeResponse encodes resp as JSON to conn.  Errors are logged, not returned,
// because the connection is about to be closed regardless.
func writeResponse(conn net.Conn, resp SocketResponse) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		slog.Debug("daemon: write response error", "err", err)
	}
}
