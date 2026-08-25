package enforce

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	cfDefaultListName = "ezyshield_blocked"
	// cfListItemTag is the comment prefix identifying EzyShield-written list
	// items. Since issue #486 items are namespaced per daemon instance —
	// "ezyshield:<instance>" — so several servers sharing one account (the
	// free plan allows a single list) each reconcile ONLY their own subset
	// instead of clobbering each other's bans on every Sync. Items with a
	// bare pre-#486 tag are "legacy": untouched unless adopt_legacy_items
	// is set on exactly one instance.
	cfListItemTag  = "ezyshield"
	cfListBatchMax = 1000 // Cloudflare bulk add/remove limit per request

	// cfListItemsPerPage is the page size requested when reading list items.
	// The API maximum is 500 — and its DEFAULT is 25, which silently capped
	// fetchAllItems at maxPages×25 = 1,250 items: real lists past that size
	// failed every Sync with "pagination exceeded 50 pages" and flipped
	// enforcement DEGRADED (issue #491, ovh1 field report).
	cfListItemsPerPage = 500

	// cfListCapWarnThreshold triggers a WARN when the shared list approaches
	// the free-plan cap (10 000 items across every instance sharing it).
	cfListCapWarnThreshold = 9000

	// cfBulkOpPollMax bounds async bulk-operation polling; combined with
	// cfBulkOpPollInterval and the limiter this is ~30s before giving up.
	cfBulkOpPollMax      = 30
	cfBulkOpPollInterval = time.Second
)

// listState tracks the desired IP set, the discovered list ID, and the IP→item
// mapping for the items THIS instance owns. The mu guards every field
// including timer.
type listState struct {
	mu         sync.Mutex
	discovered bool                // true after the first list discovery
	listID     string              // empty until discovered/created
	items      map[string]string   // ip → list item ID (owned by this instance only)
	desired    map[string]struct{} // current desired IP set
	// foreign holds IPs present in the list under someone else's ownership
	// (another EzyShield instance, a manual entry, or an add that hit the
	// API's duplicate refusal — issue #486). They are already blocked at the
	// edge, so pushes skip re-adding them; the set is cleared on every
	// removal-flush tick so an IP whose foreign owner expired it while we
	// still want it is re-added within one flush interval.
	foreign map[string]struct{}
	timer   *time.Timer
}

func newListState() *listState {
	return &listState{
		items:   make(map[string]string),
		desired: make(map[string]struct{}),
		foreign: make(map[string]struct{}),
	}
}

// CloudflareListsEnforcer maintains a single Cloudflare account-level Custom IP
// List ("Lists API") containing every ezyshield-banned IP. A single API call
// per list propagates to all zones that reference the list. When zone_ids is
// set, WAF Custom Rules are automatically managed in each zone.
//
// Ownership is per instance (issue #486): this daemon reconciles ONLY items
// carrying its own "ezyshield:<instance>" comment tag. Items written by
// other EzyShield instances sharing the account, legacy bare-"ezyshield"
// items (unless adopt_legacy_items), and manual entries are all left
// untouched on Sync/Unban — several servers can share the free plan's
// single list additively.
//
// The API token is resolved once at construction time and never logged.
type CloudflareListsEnforcer struct {
	client           *http.Client
	token            string // never logged or surfaced in errors
	instanceName     string // operator label for multi-account deployments; "" when single
	ownTag           string // "ezyshield:<instance>" — this daemon's item-comment namespace (issue #486)
	adoptLegacy      bool   // adopt pre-#486 bare-"ezyshield" items (exactly ONE instance may set this)
	accountID        string
	listName         string
	zoneIDs          []string // optional; when set, WAF rules are auto-managed per zone
	action           string   // rule action: "block" (default), "challenge", "js_challenge"
	baseURL          string
	limiter          *cfRateLimiter
	allowlist        []netip.Prefix
	debounceInterval time.Duration   // 0 = synchronous push (test mode)
	svcCtx           context.Context // bounds background debounce flushes

	// expireFlushInterval is the deferred-removal cadence (issue #445):
	// 0 = removals ride every push inline (test/synchronous mode); >0 =
	// removals batch on their own ticker so expire deletes stop hammering
	// the Lists API throttle.
	expireFlushInterval time.Duration
	// retryDelays is the backoff schedule between throttled mutation
	// attempts; empty = fail on the first throttle (test mode).
	retryDelays []time.Duration
	// opPollInterval is the async bulk-operation poll cadence.
	opPollInterval time.Duration

	state *listState
}

// NewCloudflareListsEnforcer constructs a Lists-mode enforcer from cfg.
// ctx is the service lifetime context; background debounce flushes are bounded
// by it. cfg.APIToken is resolved at construction time; the resolved value is
// not stored anywhere except this struct's private token field.
func NewCloudflareListsEnforcer(ctx context.Context, cfg *config.CloudflareCfg, allowlist []netip.Prefix) (*CloudflareListsEnforcer, error) {
	token, err := cfg.APIToken.Resolve()
	if err != nil {
		return nil, fmt.Errorf("enforce/cloudflare-lists: resolve api_token: %w", err)
	}
	if cfg.AccountID == "" {
		return nil, fmt.Errorf("enforce/cloudflare-lists: account_id is required")
	}
	listName := cfg.ListName
	if listName == "" {
		listName = cfDefaultListName
	}
	action := cfg.Action
	if action == "" {
		action = "block"
	}
	expireFlush := config.DefaultCFExpireFlushInterval
	if cfg.ExpireFlushInterval > 0 {
		expireFlush = cfg.ExpireFlushInterval.AsDuration()
	}
	e := &CloudflareListsEnforcer{
		client:              &http.Client{Timeout: 10 * time.Second},
		token:               token,
		instanceName:        cfg.Name,
		ownTag:              cfOwnTag(cfg.Instance),
		adoptLegacy:         cfg.AdoptLegacyItems,
		accountID:           cfg.AccountID,
		listName:            listName,
		zoneIDs:             cfg.ZoneIDs,
		action:              action,
		baseURL:             cfBaseURL,
		limiter:             newCFRateLimiter(cfMaxRPS),
		allowlist:           allowlist,
		debounceInterval:    cfDebounceFromCfg(cfg),
		expireFlushInterval: expireFlush,
		retryDelays:         cfRetryDelays,
		opPollInterval:      cfBulkOpPollInterval,
		svcCtx:              ctx,
		state:               newListState(),
	}
	go e.runRemovalFlusher()
	return e, nil
}

// newCFListsEnforcerForTest builds a Lists enforcer pointed at a test base URL
// with synchronous push (debounceInterval=0) and no rate limiting.
func newCFListsEnforcerForTest(token, baseURL, accountID, listName string) *CloudflareListsEnforcer {
	return newCFListsEnforcerForTestWithCtx(context.Background(), token, baseURL, accountID, listName)
}

func newCFListsEnforcerForTestWithCtx(ctx context.Context, token, baseURL, accountID, listName string) *CloudflareListsEnforcer {
	return newCFListsEnforcerForTestWithZones(ctx, token, baseURL, accountID, listName, nil)
}

func newCFListsEnforcerForTestWithZones(ctx context.Context, token, baseURL, accountID, listName string, zoneIDs []string) *CloudflareListsEnforcer {
	if listName == "" {
		listName = cfDefaultListName
	}
	return &CloudflareListsEnforcer{
		client:           &http.Client{Timeout: 5 * time.Second},
		token:            token,
		ownTag:           cfOwnTag("test-instance"), // deterministic across CI hosts
		accountID:        accountID,
		listName:         listName,
		zoneIDs:          zoneIDs,
		action:           "block",
		baseURL:          baseURL,
		limiter:          newCFRateLimiter(1000), // effectively no throttle in tests
		debounceInterval: 0,
		// expireFlushInterval 0 = removals stay inline; retryDelays empty =
		// first throttle fails immediately. Tests opt in via export_test.go.
		opPollInterval: time.Millisecond,
		svcCtx:         ctx,
		state:          newListState(),
	}
}

// NewCFListsEnforcerForTestWithZones is exported for testing WAF rule management.
func NewCFListsEnforcerForTestWithZones(ctx context.Context, token, baseURL, accountID, listName string, zoneIDs []string) *CloudflareListsEnforcer {
	return newCFListsEnforcerForTestWithZones(ctx, token, baseURL, accountID, listName, zoneIDs)
}

// Name implements sdk.Enforcer. Returns "cloudflare" for the default
// (unnamed/single-account) case to preserve backward compatibility, and
// "cloudflare[<name>]" when an instance name is configured — used by
// MultiEnforcer logging to disambiguate failures across accounts.
func (e *CloudflareListsEnforcer) Name() string {
	if e.instanceName == "" {
		return "cloudflare"
	}
	return "cloudflare[" + e.instanceName + "]"
}

// Ban adds the target IP/CIDR to the desired set and pushes (immediate or
// debounced). Refuses allowlisted targets without contacting the API.
// ASN/Country targets are not supported.
func (e *CloudflareListsEnforcer) Ban(ctx context.Context, t sdk.Target) error {
	if e.isAllowlisted(t) {
		k, _ := targetKey(t)
		return fmt.Errorf("enforce/cloudflare-lists: refusing to ban allowlisted target %s", k)
	}
	ip, err := targetKey(t)
	if err != nil {
		return fmt.Errorf("enforce/cloudflare-lists Ban: %w", err)
	}
	e.state.mu.Lock()
	e.state.desired[ip] = struct{}{}
	e.state.mu.Unlock()
	if err := e.scheduleFlush(ctx); err != nil {
		return fmt.Errorf("enforce/cloudflare-lists Ban: %w", err)
	}
	return nil
}

// Unban removes the target IP/CIDR from the desired set and pushes.
func (e *CloudflareListsEnforcer) Unban(ctx context.Context, t sdk.Target) error {
	ip, err := targetKey(t)
	if err != nil {
		return fmt.Errorf("enforce/cloudflare-lists Unban: %w", err)
	}
	e.state.mu.Lock()
	delete(e.state.desired, ip)
	e.state.mu.Unlock()
	if err := e.scheduleFlush(ctx); err != nil {
		return fmt.Errorf("enforce/cloudflare-lists Unban: %w", err)
	}
	return nil
}

// Sync replaces the desired set with exactly the given targets (modulo
// allowlist). Push is synchronous. Items not managed by ezyshield are left
// untouched. If zone_ids are configured, WAF rules are also managed per zone.
func (e *CloudflareListsEnforcer) Sync(ctx context.Context, want []sdk.Target) error {
	wantSet := make(map[string]struct{}, len(want))
	for _, t := range want {
		if e.isAllowlisted(t) {
			continue
		}
		k, err := targetKey(t)
		if err != nil {
			slog.WarnContext(ctx, "enforce/cloudflare-lists Sync: skip unsupported target", "err", err)
			continue
		}
		wantSet[k] = struct{}{}
	}
	e.state.mu.Lock()
	e.state.desired = wantSet
	if e.state.timer != nil {
		e.state.timer.Stop()
		e.state.timer = nil
	}
	e.state.mu.Unlock()
	if err := e.push(ctx); err != nil {
		return fmt.Errorf("enforce/cloudflare-lists Sync: %w", err)
	}
	if len(e.zoneIDs) > 0 {
		for _, zone := range e.zoneIDs {
			if err := e.syncZoneRule(ctx, zone); err != nil {
				return fmt.Errorf("enforce/cloudflare-lists Sync zone %s: %w", zone, err)
			}
		}
	}
	return nil
}

// scheduleFlush pushes immediately when debounceInterval==0; otherwise it (re)
// arms a single timer so rapid Ban/Unban calls are coalesced into one push.
// The background flush is bound to svcCtx, so shutdown cancels pending work.
func (e *CloudflareListsEnforcer) scheduleFlush(ctx context.Context) error {
	if e.debounceInterval == 0 {
		return e.push(ctx)
	}
	e.state.mu.Lock()
	if e.state.timer != nil {
		e.state.timer.Stop()
	}
	e.state.timer = time.AfterFunc(e.debounceInterval, func() {
		if e.svcCtx.Err() != nil {
			return
		}
		// 90s leaves room for the full throttle backoff schedule
		// (issue #445) on top of the requests themselves.
		flushCtx, cancel := context.WithTimeout(e.svcCtx, 90*time.Second)
		defer cancel()
		if err := e.push(flushCtx); err != nil {
			slog.Error("enforce/cloudflare-lists: debounced push failed", "err", err)
		}
	})
	e.state.mu.Unlock()
	return nil
}

// push discovers/creates the list as needed, then reconciles the live items
// with desired by emitting bulk add and bulk delete calls.
func (e *CloudflareListsEnforcer) push(ctx context.Context) error {
	// Snapshot the inputs under lock.
	e.state.mu.Lock()
	needsDiscover := !e.state.discovered
	listID := e.state.listID
	desiredCopy := make(map[string]struct{}, len(e.state.desired))
	for ip := range e.state.desired {
		desiredCopy[ip] = struct{}{}
	}
	itemsCopy := make(map[string]string, len(e.state.items))
	for ip, id := range e.state.items {
		itemsCopy[ip] = id
	}
	foreignCopy := make(map[string]struct{}, len(e.state.foreign))
	for ip := range e.state.foreign {
		foreignCopy[ip] = struct{}{}
	}
	e.state.mu.Unlock()

	if needsDiscover {
		newID, newItems, present, err := e.discoverList(ctx)
		if err != nil {
			return err
		}
		// Create the list when it doesn't exist yet.
		if newID == "" {
			id, createErr := e.createList(ctx)
			if createErr != nil {
				return createErr
			}
			newID = id
			newItems = make(map[string]string)
			present = make(map[string]struct{})
		}
		e.state.mu.Lock()
		e.state.discovered = true
		e.state.listID = newID
		e.state.items = newItems
		// Everything present but not ours is foreign: another instance's
		// item, a legacy item, or a manual entry (issue #486).
		e.state.foreign = make(map[string]struct{})
		for ip := range present {
			if _, mine := newItems[ip]; !mine {
				e.state.foreign[ip] = struct{}{}
			}
		}
		listID = newID
		itemsCopy = make(map[string]string, len(newItems))
		for ip, id := range newItems {
			itemsCopy[ip] = id
		}
		foreignCopy = make(map[string]struct{}, len(e.state.foreign))
		for ip := range e.state.foreign {
			foreignCopy[ip] = struct{}{}
		}
		e.state.mu.Unlock()
	}

	// Compute the diff: anything desired that we don't own yet → add. IPs
	// already present under someone else's ownership are skipped — they are
	// blocked at the edge already, and the list API refuses duplicates
	// (issue #486).
	var toAdd []string
	for ip := range desiredCopy {
		if _, mine := itemsCopy[ip]; mine {
			continue
		}
		if _, theirs := foreignCopy[ip]; theirs {
			continue
		}
		toAdd = append(toAdd, ip)
	}
	// Deterministic order so logs and tests are stable.
	sort.Strings(toAdd)

	if len(toAdd) > 0 {
		added, err := e.addItems(ctx, listID, toAdd)
		if err != nil {
			if !isCFDuplicateErr(err) {
				return err
			}
			// Another instance added one of these IPs between our discovery
			// and this push. Re-read the list to learn what is now present,
			// mark those IPs foreign, and retry the remainder once.
			var retryErr error
			if added, retryErr = e.retryAddSkippingPresent(ctx, listID, toAdd); retryErr != nil {
				return retryErr
			}
		}
		e.state.mu.Lock()
		for ip, id := range added {
			e.state.items[ip] = id
		}
		e.state.mu.Unlock()
	}

	// Removals ride the push inline only in synchronous mode
	// (expireFlushInterval == 0); in production they are deferred to the
	// removal flusher (issue #445) so expire deletes batch on their own
	// cadence instead of hammering the Lists API throttle on every push.
	if e.expireFlushInterval == 0 {
		return e.removeStale(ctx, listID, desiredCopy, itemsCopy)
	}
	return nil
}

// isCFDuplicateErr recognizes the Lists API refusing an add because the IP
// already exists in the list (added concurrently by another instance —
// issue #486). Matching on the message is best-effort; a miss just surfaces
// the original error.
func isCFDuplicateErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "duplicate")
}

// retryAddSkippingPresent handles a duplicate-refused add: re-reads the
// list, marks every already-present requested IP as foreign (blocked at the
// edge under someone else's ownership), and retries the add once for the
// IPs genuinely absent. Returns the ip→itemID map for rows this instance
// now owns.
func (e *CloudflareListsEnforcer) retryAddSkippingPresent(ctx context.Context, listID string, want []string) (map[string]string, error) {
	_, present, err := e.fetchAllItems(ctx, listID, 1)
	if err != nil {
		return nil, fmt.Errorf("duplicate-add refresh: %w", err)
	}
	var remaining []string
	e.state.mu.Lock()
	for _, ip := range want {
		if _, ok := present[ip]; ok {
			e.state.foreign[ip] = struct{}{}
			continue
		}
		remaining = append(remaining, ip)
	}
	e.state.mu.Unlock()
	if len(remaining) == 0 {
		return map[string]string{}, nil
	}
	return e.addItems(ctx, listID, remaining)
}

// removeStale deletes every managed item that is no longer desired, then
// forgets the deleted IDs. Shared by the inline (synchronous) push path and
// the deferred removal flusher.
func (e *CloudflareListsEnforcer) removeStale(ctx context.Context, listID string, desired map[string]struct{}, items map[string]string) error {
	var toRemoveIPs []string
	var toRemoveIDs []string
	for ip, id := range items {
		if _, ok := desired[ip]; !ok {
			toRemoveIPs = append(toRemoveIPs, ip)
			toRemoveIDs = append(toRemoveIDs, id)
		}
	}
	if len(toRemoveIDs) == 0 {
		return nil
	}
	if err := e.removeItems(ctx, listID, toRemoveIDs); err != nil {
		return err
	}
	e.state.mu.Lock()
	for _, ip := range toRemoveIPs {
		delete(e.state.items, ip)
	}
	e.state.mu.Unlock()
	return nil
}

// flushRemovals batches every stale item into one delete pass. A no-op
// before the first discovery — there is nothing to remove from a list that
// has not been read yet.
func (e *CloudflareListsEnforcer) flushRemovals(ctx context.Context) error {
	e.state.mu.Lock()
	// Reset the foreign cache each flush tick (issue #486): if another
	// instance expired an IP we still want, the next push re-verifies and
	// re-adds it — bounded staleness of one flush interval, fail-closed in
	// the meantime (the IP was merely blocked longer, never unblocked early).
	e.state.foreign = make(map[string]struct{})
	discovered := e.state.discovered
	listID := e.state.listID
	desiredCopy := make(map[string]struct{}, len(e.state.desired))
	for ip := range e.state.desired {
		desiredCopy[ip] = struct{}{}
	}
	itemsCopy := make(map[string]string, len(e.state.items))
	for ip, id := range e.state.items {
		itemsCopy[ip] = id
	}
	e.state.mu.Unlock()
	if !discovered || listID == "" {
		return nil
	}
	return e.removeStale(ctx, listID, desiredCopy, itemsCopy)
}

// runRemovalFlusher owns the deferred-removal cadence (issue #445). Bound to
// svcCtx; a failed flush is logged and retried on the next tick — failing to
// remove an expired item over-blocks at the edge (fail-closed), it never
// under-enforces.
func (e *CloudflareListsEnforcer) runRemovalFlusher() {
	if e.expireFlushInterval <= 0 {
		return
	}
	t := time.NewTicker(e.expireFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-e.svcCtx.Done():
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(e.svcCtx, 90*time.Second)
			if err := e.flushRemovals(ctx); err != nil {
				slog.Error("enforce/cloudflare-lists: deferred removal flush failed", "err", err)
			}
			cancel()
		}
	}
}

// ── CF Lists API discovery ────────────────────────────────────────────────────

// discoverList finds the configured list by name in the account and returns
// (listID, items owned by this instance, every IP present, nil). When the
// list is missing, returns ("", nil, nil, nil) so the caller can create it.
func (e *CloudflareListsEnforcer) discoverList(ctx context.Context) (string, map[string]string, map[string]struct{}, error) {
	if err := e.limiter.wait(ctx); err != nil {
		return "", nil, nil, err
	}
	url := fmt.Sprintf("%s/accounts/%s/rules/lists", e.baseURL, e.accountID)
	resp, err := e.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	var ls cfListListsResp
	if err := json.NewDecoder(resp.Body).Decode(&ls); err != nil {
		return "", nil, nil, fmt.Errorf("decode list lists: %w", err)
	}
	if !ls.Success {
		return "", nil, nil, fmt.Errorf("cloudflare list lists: %s", cfErrMsg(ls.Errors))
	}
	var listID string
	var numItems int
	for _, l := range ls.Result {
		if l.Name == e.listName && l.Kind == "ip" {
			listID = l.ID
			numItems = l.NumItems
			break
		}
	}
	if listID == "" {
		return "", nil, nil, nil
	}
	if numItems >= cfListCapWarnThreshold {
		// The list is shared by every instance on the account (issue #486);
		// the free plan caps it at 10 000 items total.
		slog.WarnContext(ctx, "enforce/cloudflare-lists: list is approaching the shared item cap",
			"list", e.listName, "items", numItems, "cap", 10000)
	}
	items, present, err := e.fetchAllItems(ctx, listID, numItems)
	if err != nil {
		return "", nil, nil, err
	}
	return listID, items, present, nil
}

// fetchAllItems pages through every item in the list and returns this
// instance's owned subset (ip → item ID) plus the set of EVERY IP present
// in the list regardless of owner — pushes use the latter to avoid re-adding
// an IP another instance already blocks (issue #486). The page count is
// bounded to defend against a misbehaving API that returns an unmoving
// cursor — at cfListItemsPerPage=500, 50 pages cover 25 000 items, well past
// the 10 000-item free-plan cap.
// When numItems is 0 (empty list), returns early to avoid Cloudflare API
// error 10027 (per_page on an empty list).
func (e *CloudflareListsEnforcer) fetchAllItems(ctx context.Context, listID string, numItems int) (map[string]string, map[string]struct{}, error) {
	const maxPages = 50
	owned := make(map[string]string)
	present := make(map[string]struct{})

	// Early return for empty lists: Cloudflare returns error 10027 when per_page is set on empty lists
	if numItems == 0 {
		return owned, present, nil
	}

	cursor := ""
	for page := 0; page < maxPages; page++ {
		if err := e.limiter.wait(ctx); err != nil {
			return nil, nil, err
		}
		url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items?per_page=%d",
			e.baseURL, e.accountID, listID, cfListItemsPerPage)
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		resp, err := e.doRequest(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, nil, err
		}
		var pg cfListItemsResp
		if err := json.NewDecoder(resp.Body).Decode(&pg); err != nil {
			_ = resp.Body.Close()
			return nil, nil, fmt.Errorf("decode list items: %w", err)
		}
		_ = resp.Body.Close()
		if !pg.Success {
			return nil, nil, fmt.Errorf("cloudflare list items: %s", cfErrMsg(pg.Errors))
		}
		for _, it := range pg.Result {
			if it.IP == "" {
				continue
			}
			present[it.IP] = struct{}{}
			if e.ownsItem(it.Comment) {
				owned[it.IP] = it.ID
			}
		}
		next := pg.ResultInfo.Cursors.After
		if next == "" || next == cursor {
			return owned, present, nil
		}
		cursor = next
	}
	return nil, nil, fmt.Errorf("cloudflare list items: pagination exceeded %d pages at %d items/page (unmoving cursor?)",
		maxPages, cfListItemsPerPage)
}

// ── CF Lists API mutators ────────────────────────────────────────────────────

func (e *CloudflareListsEnforcer) createList(ctx context.Context) (string, error) {
	body, err := json.Marshal(cfCreateListReq{
		Name:        e.listName,
		Kind:        "ip",
		Description: "Managed by ezyshield — do not edit items manually",
	})
	if err != nil {
		return "", fmt.Errorf("marshal create list: %w", err)
	}
	if err := e.limiter.wait(ctx); err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/accounts/%s/rules/lists", e.baseURL, e.accountID)
	resp, err := e.doRequest(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out cfCreateListResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode create list: %w", err)
	}
	if !out.Success {
		return "", fmt.Errorf("cloudflare create list: %s", cfErrMsg(out.Errors))
	}
	if out.Result == nil || out.Result.ID == "" {
		return "", fmt.Errorf("cloudflare create list: empty response")
	}
	slog.InfoContext(ctx, "enforce/cloudflare-lists: created list",
		"name", e.listName, "list_id", out.Result.ID)
	return out.Result.ID, nil
}

// mutateWithRetry executes one JSON mutation against the Lists API with
// throttle-aware retries (issue #445): HTTP 429 and the known throttle error
// codes (10040, 971) back off — jittered, honoring Retry-After — and retry up
// to len(e.retryDelays) extra attempts. Any other failure returns
// immediately. When every attempt was throttled the returned error wraps
// ErrCFThrottled so the daemon can treat the failure as transient.
func (e *CloudflareListsEnforcer) mutateWithRetry(ctx context.Context, op, method, url string, body []byte, out cfMutationResp) error {
	for attempt := 0; ; attempt++ {
		if err := e.limiter.wait(ctx); err != nil {
			return err
		}
		resp, err := e.doRequest(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		status := resp.StatusCode
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		out.reset()
		decErr := json.NewDecoder(resp.Body).Decode(out)
		_ = resp.Body.Close()
		if decErr == nil && out.ok() {
			return nil
		}
		// A throttled response may carry the JSON error envelope or (on a
		// raw 429) no parseable body at all; both retry. Everything else
		// fails now, exactly as before.
		var apiErrs []cfAPIError
		if decErr == nil {
			apiErrs = out.apiErrors()
		}
		if !cfIsThrottle(status, apiErrs) {
			if decErr != nil {
				return fmt.Errorf("decode %s: %w", op, decErr)
			}
			return fmt.Errorf("cloudflare %s: %s", op, cfErrMsg(apiErrs))
		}
		detail := fmt.Sprintf("http %d", status)
		if len(apiErrs) > 0 {
			detail = cfErrMsg(apiErrs)
		}
		if attempt >= len(e.retryDelays) {
			return fmt.Errorf("cloudflare %s: %s: %w", op, detail, ErrCFThrottled)
		}
		slog.WarnContext(ctx, "enforce/cloudflare-lists: throttled, backing off",
			"op", op, "attempt", attempt+1, "max_attempts", len(e.retryDelays)+1)
		if err := cfBackoffWait(ctx, e.retryDelays, attempt, retryAfter); err != nil {
			return err
		}
	}
}

// waitBulkOperation polls an async Lists bulk operation until it completes,
// so the next mutation never races a still-running one (issue #445 — the
// back-to-back follow-up mutation is what invites the 971 throttle).
func (e *CloudflareListsEnforcer) waitBulkOperation(ctx context.Context, opID string) error {
	url := fmt.Sprintf("%s/accounts/%s/rules/lists/bulk_operations/%s", e.baseURL, e.accountID, opID)
	for poll := 0; poll < cfBulkOpPollMax; poll++ {
		if err := e.limiter.wait(ctx); err != nil {
			return err
		}
		resp, err := e.doRequest(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		var out cfBulkOpResp
		decErr := json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()
		if decErr != nil {
			return fmt.Errorf("decode bulk operation: %w", decErr)
		}
		if !out.Success {
			return fmt.Errorf("cloudflare bulk operation: %s", cfErrMsg(out.Errors))
		}
		switch out.Result.Status {
		case "completed", "":
			// An empty status means the API answered without operation
			// detail; treat as done instead of polling an unknown shape.
			return nil
		case "failed":
			return fmt.Errorf("cloudflare bulk operation %s failed: %s", opID, out.Result.Error)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(e.opPollInterval):
		}
	}
	return fmt.Errorf("cloudflare bulk operation %s: not completed after %d polls", opID, cfBulkOpPollMax)
}

// addItems performs one bulk POST per Cloudflare batch limit and returns
// ip→itemID for the rows the API echoed back. Throttled attempts back off
// and retry (issue #445); an async operation_id is polled to completion
// before the next mutation. When the API responds with an operation_id but
// no item bodies, addItems re-reads the list once to recover the IDs.
func (e *CloudflareListsEnforcer) addItems(ctx context.Context, listID string, ips []string) (map[string]string, error) {
	out := make(map[string]string, len(ips))
	needRefresh := false
	for start := 0; start < len(ips); start += cfListBatchMax {
		end := start + cfListBatchMax
		if end > len(ips) {
			end = len(ips)
		}
		batch := ips[start:end]
		payload := make([]cfListItemReq, len(batch))
		for i, ip := range batch {
			payload[i] = cfListItemReq{IP: ip, Comment: e.ownTag}
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal add items: %w", err)
		}
		url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", e.baseURL, e.accountID, listID)
		var ar cfListAddResp
		if err := e.mutateWithRetry(ctx, "add items", http.MethodPost, url, body, &ar); err != nil {
			return nil, err
		}
		if ar.Result.OperationID != "" {
			if err := e.waitBulkOperation(ctx, ar.Result.OperationID); err != nil {
				return nil, err
			}
		}
		if len(ar.Result.Items) > 0 {
			for _, it := range ar.Result.Items {
				if it.IP != "" && it.ID != "" {
					out[it.IP] = it.ID
				}
			}
		} else {
			needRefresh = true
		}
		slog.InfoContext(ctx, "enforce/cloudflare-lists: added items",
			"count", len(batch), "list_id", listID)
	}
	if needRefresh {
		// The async path returned only an operation_id; re-page to recover IDs.
		// Pass numItems=1 as a safe default since we know items exist (we just added them).
		all, _, err := e.fetchAllItems(ctx, listID, 1)
		if err != nil {
			return nil, fmt.Errorf("post-add refresh: %w", err)
		}
		// Only copy back IPs we actually requested; preserve any IDs we already learned.
		for _, ip := range ips {
			if id, ok := all[ip]; ok {
				out[ip] = id
			}
		}
	}
	return out, nil
}

func (e *CloudflareListsEnforcer) removeItems(ctx context.Context, listID string, itemIDs []string) error {
	for start := 0; start < len(itemIDs); start += cfListBatchMax {
		end := start + cfListBatchMax
		if end > len(itemIDs) {
			end = len(itemIDs)
		}
		batch := itemIDs[start:end]
		payload := cfListDeleteReq{Items: make([]cfListDeleteItem, len(batch))}
		for i, id := range batch {
			payload.Items[i] = cfListDeleteItem{ID: id}
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal delete items: %w", err)
		}
		url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", e.baseURL, e.accountID, listID)
		var dr cfListDeleteResp
		if err := e.mutateWithRetry(ctx, "delete items", http.MethodDelete, url, body, &dr); err != nil {
			return err
		}
		if dr.Result.OperationID != "" {
			if err := e.waitBulkOperation(ctx, dr.Result.OperationID); err != nil {
				return err
			}
		}
		slog.InfoContext(ctx, "enforce/cloudflare-lists: removed items",
			"count", len(batch), "list_id", listID)
	}
	return nil
}

// ── WAF rule management (lists mode with zone_ids) ──────────────────────────

const cfListRuleDescPattern = "ezyshield-list-block"

// syncZoneRule ensures the zone has a WAF Custom Rule pointing to the list.
// On first call, discovers the ruleset and any existing ezyshield rule. On
// subsequent calls, creates or updates the rule as needed.
func (e *CloudflareListsEnforcer) syncZoneRule(ctx context.Context, zone string) error {
	// Get the current list ID (may still be discovering).
	e.state.mu.Lock()
	listID := e.state.listID
	e.state.mu.Unlock()
	if listID == "" {
		// List not yet discovered/created; can't manage rules without the list ID.
		slog.WarnContext(ctx, "enforce/cloudflare-lists: zone rule sync deferred (list not yet discovered)",
			"zone", zone)
		return nil
	}

	// Discover or create the ruleset and find existing ezyshield rule.
	rulesetID, ruleID, err := e.discoverListRuleID(ctx, zone)
	if err != nil {
		return err
	}

	expr := fmt.Sprintf("(ip.src in $%s)", listID)
	desc := cfListRuleDescPattern

	// If rule doesn't exist yet, create it.
	if ruleID == "" {
		if rulesetID == "" {
			// No ruleset at all; create one with the rule inline.
			if err := e.createListRulesetWithRule(ctx, zone, desc, expr); err != nil {
				return err
			}
			return nil
		}
		// Ruleset exists but no ezyshield rule; create the rule.
		if err := e.createListRule(ctx, zone, rulesetID, desc, expr); err != nil {
			return err
		}
		return nil
	}

	// Rule exists; check if action matches config.
	if err := e.updateListRule(ctx, zone, rulesetID, ruleID, desc, expr); err != nil {
		return err
	}
	return nil
}

// discoverListRuleID finds the zone's custom-firewall ruleset and any ezyshield
// list rule within it. Returns ("", "", nil) if the ruleset doesn't exist yet.
func (e *CloudflareListsEnforcer) discoverListRuleID(ctx context.Context, zone string) (rulesetID, ruleID string, err error) {
	// GET /zones/{zone}/rulesets to find the http_request_firewall_custom phase.
	if err := e.limiter.wait(ctx); err != nil {
		return "", "", err
	}
	url := fmt.Sprintf("%s/zones/%s/rulesets", e.baseURL, zone)
	resp, err := e.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	var ls cfListRulesetsResp
	if err := json.NewDecoder(resp.Body).Decode(&ls); err != nil {
		return "", "", fmt.Errorf("decode list rulesets: %w", err)
	}
	if !ls.Success {
		return "", "", fmt.Errorf("cloudflare list rulesets: %s", cfErrMsg(ls.Errors))
	}
	for _, rs := range ls.Result {
		if rs.Phase == cfRulePhase {
			rulesetID = rs.ID
			break
		}
	}
	if rulesetID == "" {
		return "", "", nil
	}

	// GET /zones/{zone}/rulesets/{ruleset_id} to find our managed rule.
	if err := e.limiter.wait(ctx); err != nil {
		return "", "", err
	}
	url2 := fmt.Sprintf("%s/zones/%s/rulesets/%s", e.baseURL, zone, rulesetID)
	resp2, err := e.doRequest(ctx, http.MethodGet, url2, nil)
	if err != nil {
		return "", "", err
	}
	defer resp2.Body.Close() //nolint:errcheck
	var gr cfGetRulesetResp
	if err := json.NewDecoder(resp2.Body).Decode(&gr); err != nil {
		return "", "", fmt.Errorf("decode ruleset: %w", err)
	}
	if !gr.Success {
		return "", "", fmt.Errorf("cloudflare get ruleset: %s", cfErrMsg(gr.Errors))
	}
	for _, rule := range gr.Result.Rules {
		if isManagedListRule(rule.Description) {
			ruleID = rule.ID
			break
		}
	}
	return rulesetID, ruleID, nil
}

// createListRulesetWithRule creates the http_request_firewall_custom ruleset
// with the initial ezyshield rule inline.
func (e *CloudflareListsEnforcer) createListRulesetWithRule(ctx context.Context, zone, desc, expr string) error {
	body, err := json.Marshal(cfCreateRulesetReq{
		Name:  "Custom rules",
		Kind:  "zone",
		Phase: cfRulePhase,
		Rules: []cfRuleReq{{Action: e.action, Expression: expr, Description: desc}},
	})
	if err != nil {
		return fmt.Errorf("marshal create ruleset: %w", err)
	}
	if err := e.limiter.wait(ctx); err != nil {
		return err
	}
	url := fmt.Sprintf("%s/zones/%s/rulesets", e.baseURL, zone)
	resp, err := e.doRequest(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out cfCreateRulesetResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode create ruleset: %w", err)
	}
	if !out.Success {
		return fmt.Errorf("cloudflare create ruleset: %s", cfErrMsg(out.Errors))
	}
	if len(out.Result.Rules) == 0 {
		return fmt.Errorf("cloudflare create ruleset: no rule in response")
	}
	slog.InfoContext(ctx, "enforce/cloudflare-lists: created WAF ruleset+rule",
		"zone", zone, "ruleset_id", out.Result.ID, "rule_id", out.Result.Rules[0].ID)
	return nil
}

// createListRule creates a new ezyshield WAF rule in the existing ruleset.
func (e *CloudflareListsEnforcer) createListRule(ctx context.Context, zone, rulesetID, desc, expr string) error {
	body, err := json.Marshal(cfRuleReq{Action: e.action, Expression: expr, Description: desc})
	if err != nil {
		return fmt.Errorf("marshal create rule: %w", err)
	}
	if err := e.limiter.wait(ctx); err != nil {
		return err
	}
	url := fmt.Sprintf("%s/zones/%s/rulesets/%s/rules", e.baseURL, zone, rulesetID)
	resp, err := e.doRequest(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out cfRuleWriteResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode create rule: %w", err)
	}
	if !out.Success {
		return fmt.Errorf("cloudflare create rule: %s", cfErrMsg(out.Errors))
	}
	if out.Result == nil {
		return fmt.Errorf("cloudflare create rule: empty response")
	}
	slog.InfoContext(ctx, "enforce/cloudflare-lists: created WAF rule",
		"zone", zone, "ruleset_id", rulesetID, "rule_id", out.Result.ID)
	return nil
}

// updateListRule patches the ezyshield rule to ensure the action matches config.
// The expression is updated to point to the current list ID.
func (e *CloudflareListsEnforcer) updateListRule(ctx context.Context, zone, rulesetID, ruleID, desc, expr string) error {
	body, err := json.Marshal(cfRuleReq{Action: e.action, Expression: expr, Description: desc})
	if err != nil {
		return fmt.Errorf("marshal patch rule: %w", err)
	}
	if err := e.limiter.wait(ctx); err != nil {
		return err
	}
	url := fmt.Sprintf("%s/zones/%s/rulesets/%s/rules/%s", e.baseURL, zone, rulesetID, ruleID)
	resp, err := e.doRequest(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out cfRuleWriteResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode patch rule: %w", err)
	}
	if !out.Success {
		return fmt.Errorf("cloudflare patch rule: %s", cfErrMsg(out.Errors))
	}
	slog.InfoContext(ctx, "enforce/cloudflare-lists: updated WAF rule",
		"zone", zone, "ruleset_id", rulesetID, "rule_id", ruleID)
	return nil
}

// isManagedListRule returns true when the rule's description marks it as an
// ezyshield list-mode rule (contains "ezyshield-list-block").
func isManagedListRule(desc string) bool {
	return strings.Contains(desc, cfListRuleDescPattern)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// doRequest sets auth headers and executes the HTTP request. The token never
// appears in returned errors (no %v on the URL/request).
func (e *CloudflareListsEnforcer) doRequest(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("create request %s %s: %w", method, url, err)
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http %s %s: %w", method, url, err)
	}
	return resp, nil
}

func (e *CloudflareListsEnforcer) isAllowlisted(t sdk.Target) bool {
	return targetOverlapsAllowlist(t, e.allowlist)
}

// cfOwnTag builds this daemon's item-comment namespace (issue #486):
// "ezyshield:<instance>". instance comes from config; empty falls back to
// the hostname, sanitized to [A-Za-z0-9._-] and capped at 32 bytes, with
// "default" as the last resort — the tag must be stable across restarts or
// the daemon would orphan its own items.
func cfOwnTag(instance string) string {
	if instance == "" {
		if hn, err := os.Hostname(); err == nil {
			instance = hn
		}
	}
	var b strings.Builder
	for _, r := range instance {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) > 32 {
		s = s[:32]
	}
	if s == "" {
		s = "default"
	}
	return cfListItemTag + ":" + s
}

// ownsItem reports whether this instance owns (and therefore reconciles and
// expires) a list item with the given comment. Items owned by OTHER
// EzyShield instances are treated exactly like manual items: untouched
// (issue #486 — several servers sharing one account used to clobber each
// other's bans because every instance claimed every "ezyshield" item).
func (e *CloudflareListsEnforcer) ownsItem(comment string) bool {
	if comment == e.ownTag {
		return true
	}
	return e.adoptLegacy && isLegacyManagedItem(comment)
}

// isLegacyManagedItem matches the pre-#486 tag shape: an "ezyshield" prefix
// with no ":<instance>" namespace. Ownerless by default (they would never
// expire otherwise the wrong daemon could delete them); exactly one
// instance may adopt them via adopt_legacy_items to drain them.
func isLegacyManagedItem(comment string) bool {
	return strings.HasPrefix(comment, cfListItemTag) &&
		!strings.HasPrefix(comment, cfListItemTag+":")
}

// ── Cloudflare Lists API wire types ──────────────────────────────────────────

type cfListInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	NumItems int    `json:"num_items"`
}

type cfListListsResp struct {
	Success bool         `json:"success"`
	Errors  []cfAPIError `json:"errors"`
	Result  []cfListInfo `json:"result"`
}

type cfCreateListReq struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description,omitempty"`
}

type cfCreateListResp struct {
	Success bool         `json:"success"`
	Errors  []cfAPIError `json:"errors"`
	Result  *cfListInfo  `json:"result"`
}

type cfListItem struct {
	ID      string `json:"id"`
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

type cfPageCursors struct {
	After string `json:"after"`
}

type cfPageInfo struct {
	Cursors cfPageCursors `json:"cursors"`
}

type cfListItemsResp struct {
	Success    bool         `json:"success"`
	Errors     []cfAPIError `json:"errors"`
	Result     []cfListItem `json:"result"`
	ResultInfo cfPageInfo   `json:"result_info"`
}

type cfListItemReq struct {
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

// cfListAddResult holds the synchronous-response variant of the bulk-add API.
// Cloudflare may return either an operation_id (async) or a list of created
// items (synchronous); we decode both and the caller falls back to a refetch
// when Items is empty.
type cfListAddResult struct {
	OperationID string       `json:"operation_id"`
	Items       []cfListItem `json:"-"`
}

// UnmarshalJSON accepts both Cloudflare bulk-add response shapes: an object
// with operation_id (async) and an array of items (synchronous). Unknown
// shapes are decoded to a zero value so the caller can refetch defensively.
func (r *cfListAddResult) UnmarshalJSON(data []byte) error {
	// Try the object form first ({"operation_id": "..."}).
	type objAlias struct {
		OperationID string `json:"operation_id"`
	}
	var obj objAlias
	if err := json.Unmarshal(data, &obj); err == nil && obj.OperationID != "" {
		r.OperationID = obj.OperationID
		return nil
	}
	// Otherwise expect an array of items.
	var arr []cfListItem
	if err := json.Unmarshal(data, &arr); err == nil {
		r.Items = arr
		return nil
	}
	// Fall through with an empty result so the caller refetches; this matches
	// the "unknown shape" defensive contract for untrusted API responses.
	return nil
}

type cfListAddResp struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  cfListAddResult `json:"result"`
}

type cfListDeleteItem struct {
	ID string `json:"id"`
}

type cfListDeleteReq struct {
	Items []cfListDeleteItem `json:"items"`
}

// cfListDeleteResult carries the async operation handle a bulk delete may
// return; polled to completion before the next mutation (issue #445).
type cfListDeleteResult struct {
	OperationID string `json:"operation_id"`
}

type cfListDeleteResp struct {
	Success bool               `json:"success"`
	Errors  []cfAPIError       `json:"errors"`
	Result  cfListDeleteResult `json:"result"`
}

// cfMutationResp lets mutateWithRetry check mutation outcomes generically and
// re-decode into a clean value between throttled attempts.
type cfMutationResp interface {
	ok() bool
	apiErrors() []cfAPIError
	reset()
}

func (r *cfListAddResp) ok() bool                { return r.Success }
func (r *cfListAddResp) apiErrors() []cfAPIError { return r.Errors }
func (r *cfListAddResp) reset()                  { *r = cfListAddResp{} }

func (r *cfListDeleteResp) ok() bool                { return r.Success }
func (r *cfListDeleteResp) apiErrors() []cfAPIError { return r.Errors }
func (r *cfListDeleteResp) reset()                  { *r = cfListDeleteResp{} }

// cfBulkOpResult is the status body of GET .../rules/lists/bulk_operations/{id}.
type cfBulkOpResult struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

type cfBulkOpResp struct {
	Success bool           `json:"success"`
	Errors  []cfAPIError   `json:"errors"`
	Result  cfBulkOpResult `json:"result"`
}
