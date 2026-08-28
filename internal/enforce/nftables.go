// SPDX-License-Identifier: AGPL-3.0-only

package enforce

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/internal/nftnames"
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

	// table/set are the operator-configured nftables names (issue #268),
	// already validated by nftnames.Resolve in New. Empty = helper defaults;
	// in that case they are omitted from the wire entirely, which keeps the
	// protocol byte-compatible with older helpers.
	table string
	set   string

	// capsOnce gates the one-time capability probe that runs before the
	// first RPC when non-default names are configured: an older helper
	// would silently IGNORE the Table/Set fields and enforce into its
	// default table — the exact required-but-ignored failure #268 removes —
	// so custom names hard-require the helper to advertise support.
	capsOnce sync.Once
	capsErr  error

	// initErr records an invalid WithNames configuration. Options cannot
	// return errors, and panicking in library code violates the project's
	// Go conventions (issue #358) — so the error is stored and surfaced on
	// every RPC instead: the enforcer refuses to operate rather than
	// silently enforcing into the wrong table.
	initErr error

	// repairMu guards the last-Sync repair counters (issue #214): how many
	// elements the most recent reconcile had to re-add / remove to converge
	// store and kernel. The daemon audits non-boot repairs — a mid-write
	// interruption (crash, OOM-kill) shows up here on the next reconcile
	// instead of staying silent.
	repairMu      sync.Mutex
	lastAdded     int
	lastRemoved   int
	firstSyncDone bool
	lastWasFirst  bool
}

// SyncRepairReporter is the optional sdk.Enforcer facet exposing the most
// recent Sync's drift repairs (issue #214). firstSync marks the boot
// reconcile, where re-adding every persisted ban is the EXPECTED restart
// recovery, not drift. Implemented by the nftables enforcer and forwarded by
// the Gate / MultiEnforcer wrappers (compile-time guards below).
type SyncRepairReporter interface {
	LastSyncRepairs() (added, removed int, firstSync bool)
}

// LastSyncRepairs implements SyncRepairReporter.
func (e *NftablesEnforcer) LastSyncRepairs() (added, removed int, firstSync bool) {
	e.repairMu.Lock()
	defer e.repairMu.Unlock()
	return e.lastAdded, e.lastRemoved, e.lastWasFirst
}

// Option configures a NftablesEnforcer.
type Option func(*NftablesEnforcer)

// WithNames sets the nftables table and set names from config. Values must
// already have passed config validation (nftnames.Resolve); they are
// re-resolved defensively here, and an invalid pair marks the enforcer
// broken (every RPC fails with the stored error) instead of panicking in
// library code (issue #358).
func WithNames(table, set string) Option {
	return func(e *NftablesEnforcer) {
		n, err := nftnames.Resolve(table, set)
		if err != nil {
			// Config validation should have rejected this; refuse every
			// later call instead of panicking in library code (issue #358).
			e.initErr = fmt.Errorf("enforce: invalid nftables names (config validation bypassed?): %w", err)
			return
		}
		if n.IsDefault() {
			return // defaults: keep fields empty, nothing goes on the wire
		}
		e.table = table
		e.set = set
	}
}

// New creates a NftablesEnforcer.
// socketPath defaults to DefaultSocketPath when empty.
// allowlist should mirror the policy engine's runtime allowlist.
func New(socketPath string, allowlist []netip.Prefix, opts ...Option) *NftablesEnforcer {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	e := &NftablesEnforcer{socketPath: socketPath, allowlist: allowlist}
	for _, o := range opts {
		o(e)
	}
	return e
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
// A CodeAlreadyAbsent response is intentionally collapsed into nil: `ezyshield
// unban <ip>` is defined as idempotent, and callers (CLI, admin API) already
// treat a missing target as success — surfacing the code here would just
// add ceremony without changing behaviour.
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
	added, removed := 0, 0
	for k, t := range wantSet {
		if !currentSet[k] {
			slog.InfoContext(ctx, "enforce/nftables Sync: adding", "ip", k)
			if err := e.rpc(ctx, Request{Verb: "add", IP: k, TTLSeconds: int64(t.TTL.Seconds())}); err != nil {
				return fmt.Errorf("enforce/nftables Sync add %s: %w", k, err)
			}
			added++
		}
	}

	// Remove entries present in nftables but not in the desired set.
	//
	// The delete may race with nft's per-element `timeout`: our listIPs saw
	// the element, but by the time this delete lands the kernel has already
	// expired it (issue #39). The enforcer helper signals that with a typed
	// Response.Code — we log at DEBUG and continue rather than surfacing a
	// spurious ERROR for a state we wanted anyway (element absent).
	for k := range currentSet {
		if _, ok := wantSet[k]; !ok {
			slog.InfoContext(ctx, "enforce/nftables Sync: removing stale", "ip", k)
			resp, err := e.rpcResp(ctx, Request{Verb: "del", IP: k})
			if err != nil {
				return fmt.Errorf("enforce/nftables Sync del %s: %w", k, err)
			}
			if resp.Code == CodeAlreadyAbsent {
				slog.DebugContext(ctx, "enforce/nftables Sync: element already absent (nft-native timeout)",
					"ip", k)
			} else {
				removed++
			}
		}
	}

	// Repair accounting (issue #214). The boot reconcile re-adds every
	// persisted ban into a possibly fresh kernel — expected restart
	// recovery. AFTER boot, any non-zero repair means the kernel diverged
	// from the store between reconciles (mid-write interruption, external
	// flush, helper restart): say so loudly; the daemon audits it.
	e.repairMu.Lock()
	first := !e.firstSyncDone
	e.firstSyncDone = true
	e.lastWasFirst = first
	e.lastAdded, e.lastRemoved = added, removed
	e.repairMu.Unlock()
	if (added > 0 || removed > 0) && !first {
		slog.WarnContext(ctx, "enforce/nftables Sync: repaired store↔kernel drift",
			"re_added", added, "removed", removed)
	}

	return nil
}

// listIPs sends a "list" request and returns the current set contents.
func (e *NftablesEnforcer) listIPs(ctx context.Context) ([]string, error) {
	return e.listVerb(ctx, "list")
}

// listVerb is the shared implementation of the two list verbs ("list" for
// blocked, "allow_list" for allowed). Routed through rpcResp so the request
// carries the configured table/set names like every other verb (issue #268).
func (e *NftablesEnforcer) listVerb(ctx context.Context, verb string) ([]string, error) {
	resp, err := e.rpcResp(ctx, Request{Verb: verb})
	if err != nil {
		return nil, err
	}
	return resp.IPs, nil
}

// Allow adds prefix to the nftables @allowed set via the enforcer helper.
// The allowlist supremacy invariant (AGENTS.md §2) is enforced at the same
// hook where drops happen — see initTable in cmd/ezyshield-enforcer/nft.go.
// Called by the daemon whenever an allowlist entry is added.
func (e *NftablesEnforcer) Allow(ctx context.Context, prefix netip.Prefix) error {
	return e.rpc(ctx, Request{Verb: "allow_add", IP: prefix.String()})
}

// Unallow removes prefix from the nftables @allowed set. Called when the
// operator explicitly revokes an allowlist entry or when an entry expires.
// Missing element is treated as success (idempotent, race-safe).
func (e *NftablesEnforcer) Unallow(ctx context.Context, prefix netip.Prefix) error {
	return e.rpc(ctx, Request{Verb: "allow_del", IP: prefix.String()})
}

// SyncAllowlist reconciles the nftables @allowed sets with the desired list
// of prefixes. Called at daemon startup after loading the persisted allowlist
// from the store, and after any bulk mutation. Mirrors Sync for the block set.
func (e *NftablesEnforcer) SyncAllowlist(ctx context.Context, want []netip.Prefix) error {
	current, err := e.listVerb(ctx, "allow_list")
	if err != nil {
		return fmt.Errorf("enforce/nftables SyncAllowlist list: %w", err)
	}
	currentSet := make(map[string]bool, len(current))
	for _, ip := range current {
		currentSet[ip] = true
	}
	wantSet := make(map[string]bool, len(want))
	for _, p := range want {
		wantSet[p.String()] = true
	}
	// Add missing.
	for k := range wantSet {
		if !currentSet[k] {
			slog.InfoContext(ctx, "enforce/nftables SyncAllowlist: adding", "ip", k)
			if err := e.rpc(ctx, Request{Verb: "allow_add", IP: k}); err != nil {
				return fmt.Errorf("enforce/nftables SyncAllowlist add %s: %w", k, err)
			}
		}
	}
	// Remove stale. Symmetric with Sync's del path for the same race handling
	// (issue #39, §5) — the allow set has no nft-native timeout today, but if
	// an operator flushes it out-of-band between our list and delete the
	// helper's already_absent signal must still be treated as no-op success.
	for k := range currentSet {
		if !wantSet[k] {
			slog.InfoContext(ctx, "enforce/nftables SyncAllowlist: removing stale", "ip", k)
			resp, err := e.rpcResp(ctx, Request{Verb: "allow_del", IP: k})
			if err != nil {
				return fmt.Errorf("enforce/nftables SyncAllowlist del %s: %w", k, err)
			}
			if resp.Code == CodeAlreadyAbsent {
				slog.DebugContext(ctx, "enforce/nftables SyncAllowlist: element already absent",
					"ip", k)
			}
		}
	}
	return nil
}

// FeedSyncer is the narrow surface the daemon's feed manager needs: an
// atomic desired-state replace of the reputation-feed sets (issue #195).
// Kept apart from sdk.Enforcer on purpose — feed entries are not bans and
// must never travel the strike-driven Ban/Unban/Sync paths.
type FeedSyncer interface {
	SyncFeeds(ctx context.Context, elems []FeedElement) error
}

// SyncFeeds atomically replaces the helper's reputation-feed sets
// (blocked_feeds/blocked_feeds6) with exactly elems — the helper applies one
// nft -f script (flush + re-add), so the kernel never sees partial state.
// The caller is responsible for allowlist/anti-lockout filtering BEFORE this
// point (the daemon's feed manager does; the helper additionally re-validates
// every IP). Desired sets beyond MaxFeedElements are truncated with a
// warning — the helper hard-rejects anything larger.
func (e *NftablesEnforcer) SyncFeeds(ctx context.Context, elems []FeedElement) error {
	if len(elems) > MaxFeedElements {
		slog.WarnContext(ctx, "enforce/nftables SyncFeeds: desired set exceeds cap; truncating",
			"cap", MaxFeedElements, "dropped", len(elems)-MaxFeedElements)
		elems = elems[:MaxFeedElements]
	}
	if err := e.rpc(ctx, Request{Verb: "feeds_sync", Elements: elems}); err != nil {
		if strings.Contains(err.Error(), "unknown verb") {
			return fmt.Errorf("enforce/nftables: the enforcer helper does not support feeds_sync — update ezyshield-enforcer to the same version as ezyshield: %w", err)
		}
		return fmt.Errorf("enforce/nftables SyncFeeds: %w", err)
	}
	return nil
}

// rpc sends a request and returns nil on OK, else a wrapped error. Callers
// that need to inspect Response.Code (e.g. the Sync loops, to distinguish
// "already absent" from a real success) should use rpcResp instead.
func (e *NftablesEnforcer) rpc(ctx context.Context, req Request) error {
	_, err := e.rpcResp(ctx, req)
	return err
}

// rpcResp is the shared low-level RPC: it sends req, decodes the response,
// and returns the typed Response so callers can dispatch on Response.Code.
// Non-OK responses return a wrapped error (matching rpc's contract).
func (e *NftablesEnforcer) rpcResp(ctx context.Context, req Request) (Response, error) {
	var resp Response
	if e.initErr != nil {
		return resp, e.initErr
	}
	// Custom names ride on every request (the helper pins them on first
	// use); default names stay off the wire for old-helper compatibility.
	req.Table = e.table
	req.Set = e.set
	if err := e.ensureCustomNamesSupported(ctx); err != nil {
		return resp, err
	}
	conn, err := e.dial(ctx)
	if err != nil {
		return resp, err
	}
	defer conn.Close() //nolint:errcheck

	if err := sendRequest(conn, req); err != nil {
		return resp, err
	}
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return resp, fmt.Errorf("enforce/nftables: decode response: %w", err)
	}
	if !resp.OK {
		return resp, fmt.Errorf("enforce/nftables %s: %s", req.Verb, resp.Error)
	}
	return resp, nil
}

// ensureCustomNamesSupported probes the helper's capabilities exactly once
// when non-default names are configured. A helper that predates the "caps"
// verb answers with an unknown-verb error — with custom names configured
// that is FATAL for every subsequent call: enforcing into the default table
// while config names another would be a silent divergence (issue #268).
func (e *NftablesEnforcer) ensureCustomNamesSupported(ctx context.Context) error {
	if e.table == "" && e.set == "" {
		return nil
	}
	e.capsOnce.Do(func() {
		conn, err := e.dial(ctx)
		if err != nil {
			// Transient dial failure must not poison the sync.Once with a
			// permanent verdict — leave capsErr nil and let the actual RPC
			// fail with the dial error; the probe re-runs conceptually on
			// the next process start. (A helper that is down is a different
			// failure class than a helper that is too old.)
			return
		}
		defer conn.Close() //nolint:errcheck
		if err := sendRequest(conn, Request{Verb: "caps"}); err != nil {
			return
		}
		var resp Response
		if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
			return
		}
		if !resp.OK {
			e.capsErr = fmt.Errorf("enforce/nftables: custom table/set names configured (%q/%q) but the enforcer helper does not support them (%s) — update ezyshield-enforcer to the same version as ezyshield, or remove enforce.nftables.table/set to use the defaults",
				e.table, e.set, resp.Error)
			return
		}
		for _, f := range resp.Features {
			if f == FeatureCustomNames {
				return
			}
		}
		e.capsErr = fmt.Errorf("enforce/nftables: custom table/set names configured (%q/%q) but the enforcer helper does not advertise %s support (features: %s) — update ezyshield-enforcer",
			e.table, e.set, FeatureCustomNames, strings.Join(resp.Features, ","))
	})
	return e.capsErr
}

func (e *NftablesEnforcer) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", e.socketPath)
	if err != nil {
		return nil, fmt.Errorf("enforce/nftables: dial %s: %w", e.socketPath, err)
	}
	return conn, nil
}

// isAllowlisted returns true if the target overlaps any entry in the
// enforcer's allowlist copy.
func (e *NftablesEnforcer) isAllowlisted(t sdk.Target) bool {
	return targetOverlapsAllowlist(t, e.allowlist)
}

// targetOverlapsAllowlist is the shared belt-and-suspenders allowlist check
// for every enforcer: Overlaps for prefix targets (the Gate's semantics),
// Contains for single addresses. Comparing only the prefix's BASE address
// let a CIDR ban that merely CONTAINS an allowlisted host pass the check —
// the documented protection against accidental direct invocation did not
// hold for CIDR targets (issue #358).
func targetOverlapsAllowlist(t sdk.Target, allowlist []netip.Prefix) bool {
	if t.Prefix.IsValid() {
		for _, p := range allowlist {
			if t.Prefix.Overlaps(p) {
				return true
			}
		}
		return false
	}
	if t.IP.IsValid() {
		for _, p := range allowlist {
			if p.Contains(t.IP) {
				return true
			}
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

// Compile-time guards: the wrappers must keep forwarding the repair facet
// (issue #214) — mirrors the AllowlistSyncer guard discipline (issue #317).
var (
	_ SyncRepairReporter = (*NftablesEnforcer)(nil)
	_ SyncRepairReporter = (*Gate)(nil)
	_ SyncRepairReporter = (*MultiEnforcer)(nil)
)
