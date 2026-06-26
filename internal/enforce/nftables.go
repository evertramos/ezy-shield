package enforce

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// DefaultSocketPath is the unix socket used by the enforcer helper.
const DefaultSocketPath = "/run/ezyshield-enforcer/enforcer.sock"

// NftablesEnforcer sends ban/unban/sync commands to the privileged
// ezyshield-enforcer helper over a unix socket (JSON lines).
//
// Belt-and-suspenders: the allowlist is re-checked here before every Ban call
// so that an accidental direct invocation cannot bypass the decision engine's
// primary allowlist guard (AGENTS.md Hard Rule §1).
type NftablesEnforcer struct {
	socketPath string
	allowlist  []netip.Prefix
}

// New creates a NftablesEnforcer.
// socketPath defaults to DefaultSocketPath when empty.
// allowlist should mirror the policy engine's runtime allowlist.
func New(socketPath string, allowlist []netip.Prefix) *NftablesEnforcer {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &NftablesEnforcer{socketPath: socketPath, allowlist: allowlist}
}

// Name implements sdk.Enforcer.
func (e *NftablesEnforcer) Name() string { return "nftables" }

// Ban adds the target to the nftables blocked set via the enforcer helper.
// Returns an error without contacting the helper if the target is allowlisted.
func (e *NftablesEnforcer) Ban(ctx context.Context, t sdk.Target) error {
	if e.isAllowlisted(t) {
		k, _ := targetKey(t)
		return fmt.Errorf("enforce/nftables: refusing to ban allowlisted target %s", k)
	}
	ip, err := targetKey(t)
	if err != nil {
		return fmt.Errorf("enforce/nftables Ban: %w", err)
	}
	return e.rpc(ctx, Request{Verb: "add", IP: ip, TTLSeconds: int64(t.TTL.Seconds())})
}

// Unban removes the target from the nftables blocked set via the enforcer helper.
func (e *NftablesEnforcer) Unban(ctx context.Context, t sdk.Target) error {
	ip, err := targetKey(t)
	if err != nil {
		return fmt.Errorf("enforce/nftables Unban: %w", err)
	}
	return e.rpc(ctx, Request{Verb: "del", IP: ip})
}

// Sync reconciles the nftables blocked set with the desired target list.
// It is called at daemon startup (to apply bans_active) and periodically.
// Allowlisted targets in want are silently skipped.
func (e *NftablesEnforcer) Sync(ctx context.Context, want []sdk.Target) error {
	current, err := e.listIPs(ctx)
	if err != nil {
		return fmt.Errorf("enforce/nftables Sync list: %w", err)
	}

	currentSet := make(map[string]bool, len(current))
	for _, ip := range current {
		currentSet[ip] = true
	}

	wantSet := make(map[string]sdk.Target, len(want))
	for _, t := range want {
		if e.isAllowlisted(t) {
			continue
		}
		k, err := targetKey(t)
		if err != nil {
			slog.WarnContext(ctx, "enforce/nftables Sync: skip unsupported target", "err", err)
			continue
		}
		wantSet[k] = t
	}

	// Add entries missing from nftables.
	for k, t := range wantSet {
		if !currentSet[k] {
			slog.InfoContext(ctx, "enforce/nftables Sync: adding", "ip", k)
			if err := e.rpc(ctx, Request{Verb: "add", IP: k, TTLSeconds: int64(t.TTL.Seconds())}); err != nil {
				return fmt.Errorf("enforce/nftables Sync add %s: %w", k, err)
			}
		}
	}

	// Remove entries present in nftables but not in the desired set.
	for k := range currentSet {
		if _, ok := wantSet[k]; !ok {
			slog.InfoContext(ctx, "enforce/nftables Sync: removing stale", "ip", k)
			if err := e.rpc(ctx, Request{Verb: "del", IP: k}); err != nil {
				return fmt.Errorf("enforce/nftables Sync del %s: %w", k, err)
			}
		}
	}

	return nil
}

// listIPs sends a "list" request and returns the current set contents.
func (e *NftablesEnforcer) listIPs(ctx context.Context) ([]string, error) {
	conn, err := e.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck

	if err := sendRequest(conn, Request{Verb: "list"}); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("enforce/nftables: decode list response: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("enforce/nftables: list: %s", resp.Error)
	}
	return resp.IPs, nil
}

// rpc sends a request and checks the response is OK.
func (e *NftablesEnforcer) rpc(ctx context.Context, req Request) error {
	conn, err := e.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	if err := sendRequest(conn, req); err != nil {
		return err
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return fmt.Errorf("enforce/nftables: decode response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("enforce/nftables %s: %s", req.Verb, resp.Error)
	}
	return nil
}

func (e *NftablesEnforcer) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", e.socketPath)
	if err != nil {
		return nil, fmt.Errorf("enforce/nftables: dial %s: %w", e.socketPath, err)
	}
	return conn, nil
}

// isAllowlisted returns true if the target's address is covered by any
// entry in the enforcer's allowlist copy.
func (e *NftablesEnforcer) isAllowlisted(t sdk.Target) bool {
	addr, ok := targetAddr(t)
	if !ok {
		return false
	}
	for _, p := range e.allowlist {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// targetKey returns the canonical string representation of a target
// for use as the IP field in a Request ("1.2.3.4", "10.0.0.0/8", ...).
// Returns an error for ASN/Country targets (not handled by nftables enforcer).
func targetKey(t sdk.Target) (string, error) {
	if t.IP.IsValid() {
		return t.IP.String(), nil
	}
	if t.Prefix.IsValid() {
		return t.Prefix.String(), nil
	}
	return "", fmt.Errorf("target must have IP or Prefix set (ASN/Country not supported by nftables enforcer)")
}

// targetAddr returns the primary address of a target for allowlist comparison.
func targetAddr(t sdk.Target) (netip.Addr, bool) {
	if t.IP.IsValid() {
		return t.IP, true
	}
	if t.Prefix.IsValid() {
		return t.Prefix.Addr(), true
	}
	return netip.Addr{}, false
}

// sendRequest marshals req as a JSON line and writes it to conn.
func sendRequest(conn net.Conn, req Request) error {
	b, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("enforce/nftables: marshal request: %w", err)
	}
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		return fmt.Errorf("enforce/nftables: write request: %w", err)
	}
	return nil
}
