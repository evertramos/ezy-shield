package daemon

// Reputation-feed enforcement (issue #195). The feeds package (#194)
// downloads and sanitizes the entries; run.go injects its refresh loop via
// Config.FeedUpdates (so the daemon never imports internal/feeds), and this
// file decides what the entries are allowed to DO:
//
//   - Every update is filtered through the daemon's own guardrails FIRST:
//     allowlist/admin CIDRs, active SSH peers, and shared CDN ranges. A
//     poisoned feed cannot override Hard Rule §1 or the anti-lockout
//     invariants — the enforcer-side gate never even sees the entry.
//   - action:observe feeds live only in memory, as a reputation flag that
//     boosts rule-engine scores when the IP also shows up in LOCAL events.
//   - action:block feeds are reconciled wholesale into the dedicated
//     blocked_feeds nftables sets via the helper's atomic feeds_sync verb —
//     never through Ban/Sync, never into bans_active, never as strikes.
//   - armed:false (dry-run) writes nothing to the firewall; it logs what
//     would apply.
//   - Each refresh leaves ONE audit row summarizing added/removed/skipped —
//     not one row per IP.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/internal/cdndetect"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/internal/enforce"
)

// feedReputationBoost is added to every rule verdict score for an IP that a
// reputation feed flags (capped at 100). A boost, not a verdict: a feed
// alone never bans — the IP must already be tripping local rules.
const feedReputationBoost = 15

// FeedUpdate is one sanitized feed refresh delivered to the daemon by the
// injected fetch loop.
type FeedUpdate struct {
	// Name is the feed's configured name.
	Name string
	// Action is "observe" or "block" (config-validated).
	Action string
	// TTL is the nft per-element timeout for block entries.
	TTL time.Duration
	// Interval is the feed's refresh cadence (status reporting only).
	Interval time.Duration
	// Prefixes is the deduplicated, reserved-range-sanitized entry set.
	Prefixes []netip.Prefix
}

// FeedStatusEntry is one feed's state in the "feeds_status" socket response
// (issue #196).
type FeedStatusEntry struct {
	Name        string    `json:"name"`
	Action      string    `json:"action"`
	LastRefresh time.Time `json:"last_refresh"`
	NextRefresh time.Time `json:"next_refresh,omitempty"`
	Entries     int       `json:"entries"`
	Skipped     int       `json:"skipped"`
}

// feedReputation is the in-memory observe-mode lookup: exact map for host
// prefixes (the vast majority), linear scan for wider ones.
type feedReputation struct {
	mu    sync.RWMutex
	hosts map[netip.Addr]string // addr → feed name
	wide  []feedWidePrefix
}

type feedWidePrefix struct {
	prefix netip.Prefix
	feed   string
}

func newFeedReputation() *feedReputation {
	return &feedReputation{hosts: map[netip.Addr]string{}}
}

// set replaces one feed's entries.
func (r *feedReputation) set(feed string, prefixes []netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for a, f := range r.hosts {
		if f == feed {
			delete(r.hosts, a)
		}
	}
	wide := r.wide[:0]
	for _, w := range r.wide {
		if w.feed != feed {
			wide = append(wide, w)
		}
	}
	r.wide = wide
	for _, p := range prefixes {
		if p.IsSingleIP() {
			r.hosts[p.Addr()] = feed
		} else {
			r.wide = append(r.wide, feedWidePrefix{prefix: p, feed: feed})
		}
	}
}

// Lookup reports which feed (if any) flags addr.
func (r *feedReputation) Lookup(addr netip.Addr) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a := addr.Unmap()
	if f, ok := r.hosts[a]; ok {
		return f, true
	}
	for _, w := range r.wide {
		if w.prefix.Contains(a) {
			return w.feed, true
		}
	}
	return "", false
}

// handleFeedUpdate processes one refresh: guardrail filtering, then the
// observe or block path, then a single audit summary row.
func (d *Daemon) handleFeedUpdate(ctx context.Context, u FeedUpdate) {
	kept, skipped := d.filterFeedEntries(u.Prefixes)

	var applied, removed int
	switch u.Action {
	case "block":
		applied, removed = d.applyFeedBlock(ctx, u, kept)
	default: // observe
		d.feedMu.Lock()
		prev := d.feedObserved[u.Name]
		d.feedObserved[u.Name] = len(kept)
		d.feedMu.Unlock()
		d.feedRep.set(u.Name, kept)
		applied = len(kept)
		if prev > applied {
			removed = prev - applied
		}
	}

	// Status for the "feeds_status" socket verb (issue #196).
	st := FeedStatusEntry{
		Name:        u.Name,
		Action:      u.Action,
		LastRefresh: time.Now(),
		Entries:     applied,
		Skipped:     skipped,
	}
	if u.Action == "" {
		st.Action = "observe"
	}
	if u.Interval > 0 {
		st.NextRefresh = st.LastRefresh.Add(u.Interval)
	}
	d.feedMu.Lock()
	d.feedStatus[u.Name] = st
	d.feedMu.Unlock()

	summary := fmt.Sprintf("feed %s (%s): entries=%d skipped_by_guardrails=%d removed=%d ttl=%s",
		u.Name, u.Action, applied, skipped, removed, u.TTL)
	slog.InfoContext(ctx, "daemon: feed refresh", "feed", u.Name, "action", u.Action,
		"entries", applied, "skipped_guardrails", skipped)
	if err := d.store.AuditSystem(ctx, "feed_refresh", summary); err != nil {
		slog.ErrorContext(ctx, "daemon: audit feed_refresh", "err", err)
	}
}

// filterFeedEntries drops every entry the daemon's guardrails protect:
// allowlist/admin CIDRs, active SSH peers, shared CDN ranges. Overlap in
// either direction counts — a broad feed prefix covering an allowlisted
// host is just as dangerous as the host itself.
func (d *Daemon) filterFeedEntries(prefixes []netip.Prefix) (kept []netip.Prefix, skipped int) {
	peers := d.feedSSHPeers()
	cdn, cdnErr := cdndetect.SharedRanges()
	if cdnErr != nil {
		// Detection data unavailable is a known state (doctor reports it);
		// the other guards still apply.
		cdn = nil
	}
	for _, p := range prefixes {
		if d.feedEntryGuarded(p, peers, cdn) {
			skipped++
			continue
		}
		kept = append(kept, p)
	}
	return kept, skipped
}

func (d *Daemon) feedEntryGuarded(p netip.Prefix, peers []netip.Addr, cdn []netip.Prefix) bool {
	for _, a := range d.staticAllowlist {
		if a.Overlaps(p) {
			return true
		}
	}
	for _, peer := range peers {
		if p.Contains(peer.Unmap()) {
			return true
		}
	}
	for _, c := range cdn {
		if c.Overlaps(p) {
			return true
		}
	}
	return false
}

// feedSSHPeers resolves the active operator SSH peers (injectable in tests).
func (d *Daemon) feedSSHPeers() []netip.Addr {
	if d.feedSSHPeersFn != nil {
		return d.feedSSHPeersFn()
	}
	return decision.ProcSSHPeers()
}

// applyFeedBlock updates the per-feed desired state and reconciles the full
// combined desired set into the helper's feed sets. Returns how many entries
// this feed contributes and how many its previous state lost.
func (d *Daemon) applyFeedBlock(ctx context.Context, u FeedUpdate, kept []netip.Prefix) (applied, removed int) {
	ttl := u.TTL
	if ttl <= 0 {
		ttl = time.Hour // defensive; run.go always sets it
	}
	elems := make([]enforce.FeedElement, 0, len(kept))
	for _, p := range kept {
		ip := p.String()
		if p.IsSingleIP() {
			ip = p.Addr().String()
		}
		elems = append(elems, enforce.FeedElement{IP: ip, TTLSeconds: int64(ttl.Seconds())})
	}

	d.feedMu.Lock()
	prev := len(d.feedBlockDesired[u.Name])
	d.feedBlockDesired[u.Name] = elems
	var combined []enforce.FeedElement
	for _, es := range d.feedBlockDesired {
		combined = append(combined, es...)
	}
	d.feedMu.Unlock()

	applied = len(elems)
	if prev > applied {
		removed = prev - applied
	}

	if !d.policy.IsArmed() {
		slog.InfoContext(ctx, "daemon: feeds dry-run — would apply blocklist (armed=false, no firewall write)",
			"feed", u.Name, "entries", applied, "combined_total", len(combined))
		return applied, removed
	}
	if d.feedSyncer == nil {
		slog.WarnContext(ctx, "daemon: feed has action=block but no nftables enforcer is configured; entries observed only",
			"feed", u.Name)
		return applied, removed
	}
	if err := d.feedSyncer.SyncFeeds(ctx, combined); err != nil {
		slog.ErrorContext(ctx, "daemon: feeds sync failed", "feed", u.Name, "err", err)
	}
	return applied, removed
}

// runFeeds starts the injected feed refresh loop, if any.
func (d *Daemon) runFeeds(ctx context.Context) {
	if d.feedUpdates == nil {
		return
	}
	d.feedUpdates(ctx, func(u FeedUpdate) {
		d.handleFeedUpdate(ctx, u)
	})
}

// handleFeedsStatus serves the "feeds_status" socket verb (issue #196).
func (d *Daemon) handleFeedsStatus(_ context.Context) SocketResponse {
	if d.feedUpdates == nil && d.feedRefresh == nil {
		return SocketResponse{Error: "no reputation feeds configured (config.yaml 'feeds' section)"}
	}
	data, err := json.Marshal(d.feedsStatusSnapshot())
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("encode feeds status: %v", err)}
	}
	return SocketResponse{OK: true, Data: data}
}

// handleFeedsRefresh serves the "feeds_refresh" socket verb (issue #196):
// a synchronous on-demand re-fetch of one feed (req.Name) or all feeds.
func (d *Daemon) handleFeedsRefresh(ctx context.Context, req SocketRequest) SocketResponse {
	if d.feedRefresh == nil {
		return SocketResponse{Error: "no reputation feeds configured (config.yaml 'feeds' section)"}
	}
	n, err := d.feedRefresh(ctx, req.Name, func(u FeedUpdate) {
		d.handleFeedUpdate(ctx, u)
	})
	if err != nil {
		return SocketResponse{Error: err.Error()}
	}
	data, err := json.Marshal(FeedsRefreshData{Refreshed: n})
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("encode refresh result: %v", err)}
	}
	return SocketResponse{OK: true, Data: data}
}

// FeedsRefreshData is the Data payload of a successful "feeds_refresh".
type FeedsRefreshData struct {
	Refreshed int `json:"refreshed"`
}

// feedsStatusSnapshot returns the per-feed status entries, sorted by name.
func (d *Daemon) feedsStatusSnapshot() []FeedStatusEntry {
	d.feedMu.Lock()
	defer d.feedMu.Unlock()
	out := make([]FeedStatusEntry, 0, len(d.feedStatus))
	for _, st := range d.feedStatus {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
