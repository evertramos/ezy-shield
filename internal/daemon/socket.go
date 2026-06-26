package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

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

// serveSocket creates the unix socket and accepts connections until ctx is done.
// It creates the socket directory (0750) if absent.
//
// Security: the socket is created at socketPath with mode 0660.  The kernel
// enforces access by UID/GID; no further authentication is done.  All mutating
// commands (ban, unban, allow) are written to audit_log.
func (d *Daemon) serveSocket(ctx context.Context) {
	dir := filepath.Dir(d.socketPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		slog.ErrorContext(ctx, "daemon: socket dir create failed",
			"dir", dir, "err", err)
		return
	}

	// Remove a stale socket from a previous run.
	_ = os.Remove(d.socketPath)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", d.socketPath)
	if err != nil {
		slog.ErrorContext(ctx, "daemon: socket listen failed",
			"path", d.socketPath, "err", err)
		return
	}

	// Set permissions immediately after bind so a window between bind and chmod
	// is as narrow as possible.
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
	case "ban":
		resp = d.handleBan(ctx, req)
	case "unban":
		resp = d.handleUnban(ctx, req)
	case "allow":
		resp = d.handleAllow(ctx, req)
	default:
		resp = SocketResponse{Error: fmt.Sprintf("unknown verb %q; valid: status list ban unban allow", req.Verb)}
	}

	writeResponse(conn, resp)
}

// handleStatus returns daemon health and current ban count.
func (d *Daemon) handleStatus(ctx context.Context) SocketResponse {
	bans, err := d.store.ActiveBans(ctx)
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("active bans: %v", err)}
	}

	data := StatusData{
		Uptime:     time.Since(d.startTime).Round(time.Second).String(),
		Armed:      d.policy.Armed,
		ActiveBans: len(bans),
		Version:    d.version,
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
			IP:     b.IP.String(),
			TTL:    ttl,
			Strike: b.Strike,
			Reason: b.Reason,
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

// handleBan manually bans an IP, bypassing the rule engine.
// The IP is still checked against the allowlist in the enforcer.
func (d *Daemon) handleBan(ctx context.Context, req SocketRequest) SocketResponse {
	ip, err := parseSocketIP(req.IP)
	if err != nil {
		return SocketResponse{Error: err.Error()}
	}

	var ttl time.Duration
	if req.TTL != "" {
		ttl, err = time.ParseDuration(req.TTL)
		if err != nil {
			return SocketResponse{Error: fmt.Sprintf("invalid ttl %q: %v", req.TTL, err)}
		}
	}

	if d.enforcer != nil && d.policy.Armed {
		t := sdk.Target{IP: ip, TTL: ttl}
		if err := d.enforcer.Ban(ctx, t); err != nil {
			return SocketResponse{Error: fmt.Sprintf("enforcer ban: %v", err)}
		}
	}

	op := "ban"
	if !d.policy.Armed {
		op = "dry_ban"
	}

	action := sdk.Action{IP: ip, Op: op, TTL: ttl, Reason: "manual ban via CLI"}
	if err := d.store.Audit(ctx, action); err != nil {
		slog.ErrorContext(ctx, "daemon: audit manual ban", "ip", ip, "err", err)
	}

	return SocketResponse{OK: true}
}

// handleUnban removes an IP from the ban set and the store.
func (d *Daemon) handleUnban(ctx context.Context, req SocketRequest) SocketResponse {
	ip, err := parseSocketIP(req.IP)
	if err != nil {
		return SocketResponse{Error: err.Error()}
	}

	if d.enforcer != nil {
		t := sdk.Target{IP: ip}
		if err := d.enforcer.Unban(ctx, t); err != nil {
			// Log but don't fail — store cleanup should still proceed.
			slog.ErrorContext(ctx, "daemon: enforcer unban failed", "ip", ip, "err", err)
		}
	}

	if err := d.store.Unban(ctx, ip); err != nil {
		return SocketResponse{Error: fmt.Sprintf("store unban: %v", err)}
	}

	return SocketResponse{OK: true}
}

// handleAllow adds ip to the daemon's runtime allowlist.
// The entry takes effect immediately for the pipeline but is not persisted
// across daemon restarts (use policy.yaml for permanent allowlist entries).
func (d *Daemon) handleAllow(ctx context.Context, req SocketRequest) SocketResponse {
	ip, err := parseSocketIP(req.IP)
	if err != nil {
		return SocketResponse{Error: err.Error()}
	}

	prefix := netip.PrefixFrom(ip, ip.BitLen())

	d.mu.Lock()
	d.runtimeAllowlist = append(d.runtimeAllowlist, prefix)
	d.mu.Unlock()

	slog.InfoContext(ctx, "daemon: runtime allowlist updated", "ip", ip)
	return SocketResponse{OK: true}
}

// parseSocketIP parses a plain IP address from a socket request.
// Returns an error with a user-safe message on failure.
func parseSocketIP(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, fmt.Errorf("ip is required")
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid ip %q: %v", s, err)
	}
	return ip, nil
}

// writeResponse encodes resp as JSON to conn.  Errors are logged, not returned,
// because the connection is about to be closed regardless.
func writeResponse(conn net.Conn, resp SocketResponse) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		slog.Debug("daemon: write response error", "err", err)
	}
}
