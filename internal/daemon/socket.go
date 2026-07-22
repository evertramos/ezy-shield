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

	"github.com/evertramos/ezy-shield/internal/ownership"
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
)

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

	// Remove a stale socket from a previous run — ProbeSocket in Run has
	// already confirmed nothing is listening here.
	_ = os.Remove(d.socketPath)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", d.socketPath)
	if err != nil {
		slog.ErrorContext(ctx, "daemon: socket listen failed",
			"path", d.socketPath, "err", err)
		return
	}

	// Set permissions immediately after bind so a window between bind and chmod
	// is as narrow as possible. The standard for security daemons (fail2ban,
	// sshguard) is group=ezyshield 0660 so admins in the group can use the
	// control socket without sudo — see issue #6.
	if err := ownership.ChownToGroup(d.socketPath, ownership.Group); err != nil {
		slog.WarnContext(ctx, "daemon: could not set control socket group; admins may need sudo until 'ezyshield init' creates the group",
			"path", d.socketPath, "group", ownership.Group, "err", err)
	}
	if err := os.Chmod(d.socketPath, socketPerm); err != nil {
		slog.WarnContext(ctx, "daemon: socket chmod failed",
			"path", d.socketPath, "err", err)
	}

	slog.InfoContext(ctx, "daemon: control socket listening", "path", d.socketPath)

	// Close the listener when the context is cancelled so Accept unblocks.
	// The ListenConfig.Listen call already wires ctx cancellation to ln.Close()
	// for the common case, but we add explicit cleanup for safety.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // expected: context cancelled
			}
			slog.ErrorContext(ctx, "daemon: socket accept error", "err", err)
			continue
		}
		go d.handleConn(ctx, conn)
	}
}

// handleConn decodes one SocketRequest, dispatches it, and encodes the response.
func (d *Daemon) handleConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(connDeadline)
	_ = conn.SetDeadline(deadline)

	var req SocketRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeResponse(conn, SocketResponse{Error: fmt.Sprintf("decode request: %v", err)})
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
	case "ban":
		resp = d.handleBan(ctx, req)
	case "unban":
		resp = d.handleUnban(ctx, req)
	case "allow":
		resp = d.handleAllow(ctx, req)
	default:
		resp = SocketResponse{Error: fmt.Sprintf("unknown verb %q; valid: status list list_allow events subscribe report ban unban allow", req.Verb)}
	}

	writeResponse(conn, resp)
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

	data := StatusData{
		Uptime:        time.Since(d.startTime).Round(time.Second).String(),
		Armed:         d.policy.Armed,
		ActiveBans:    active,
		SimulatedBans: simulated,
		Version:       d.version,
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
		ttl := "permanent"
		if b.TTL > 0 {
			ttl = b.TTL.Round(time.Second).String()
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

// handleBan manually bans an IP or CIDR, bypassing the rule engine.
// The target is still checked against the allowlist in the enforcer.
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

	if d.enforcer != nil && d.policy.Armed {
		t := targetFromPrefix(prefix, ttl)
		if err := d.enforcer.Ban(ctx, t); err != nil {
			return SocketResponse{Error: fmt.Sprintf("enforcer ban: %v", err)}
		}
	}

	op := "ban"
	if !d.policy.Armed {
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
	stored := false
	if prefix.Bits() == prefix.Addr().BitLen() && d.policy.Armed {
		if err := d.store.RecordManualBan(ctx, prefix.Addr(), ttl, reason); err != nil {
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

// handleEvents returns the last N audit_log rows in reverse chronological
// order. It is read-only; the append-only invariant on audit_log is
// unaffected. Limit defaults to 100 and is capped at 1000 by the store.
func (d *Daemon) handleEvents(ctx context.Context, req SocketRequest) SocketResponse {
	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.store.ListAuditLog(ctx, limit)
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
func parseSocketTarget(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("ip or cidr is required")
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid ip or cidr %q", s)
	}
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
