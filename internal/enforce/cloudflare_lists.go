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
	"sort"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	cfDefaultListName = "ezyshield_blocked"
	cfListItemTag     = "ezyshield"
	cfListItemPerPage = 1000 // Cloudflare max page size for list items
	cfListBatchMax    = 1000 // Cloudflare bulk add/remove limit per request
)

// listState tracks the desired IP set, the discovered list ID, and the IP→item
// mapping for ezyshield-managed items. The mu guards every field including timer.
type listState struct {
	mu         sync.Mutex
	discovered bool                // true after the first list discovery
	listID     string              // empty until discovered/created
	items      map[string]string   // ip → list item ID (ezyshield-managed only)
	desired    map[string]struct{} // current desired IP set
	timer      *time.Timer
}

func newListState() *listState {
	return &listState{
		items:   make(map[string]string),
		desired: make(map[string]struct{}),
	}
}

// CloudflareListsEnforcer maintains a single Cloudflare account-level Custom IP
// List ("Lists API") containing every ezyshield-banned IP. A single API call
// per list propagates to all zones that reference the list via a WAF Custom
// Rule (operator-created, once).
//
// Only items whose comment starts with cfListItemTag are considered managed —
// items added manually outside ezyshield are left untouched on Sync/Unban.
//
// The API token is resolved once at construction time and never logged.
type CloudflareListsEnforcer struct {
	client           *http.Client
	token            string // never logged or surfaced in errors
	accountID        string
	listName         string
	baseURL          string
	limiter          *cfRateLimiter
	allowlist        []netip.Prefix
	debounceInterval time.Duration   // 0 = synchronous push (test mode)
	svcCtx           context.Context // bounds background debounce flushes

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
	return &CloudflareListsEnforcer{
		client:           &http.Client{Timeout: 10 * time.Second},
		token:            token,
		accountID:        cfg.AccountID,
		listName:         listName,
		baseURL:          cfBaseURL,
		limiter:          newCFRateLimiter(cfMaxRPS),
		allowlist:        allowlist,
		debounceInterval: cfDebounceTime,
		svcCtx:           ctx,
		state:            newListState(),
	}, nil
}

// newCFListsEnforcerForTest builds a Lists enforcer pointed at a test base URL
// with synchronous push (debounceInterval=0) and no rate limiting.
func newCFListsEnforcerForTest(token, baseURL, accountID, listName string) *CloudflareListsEnforcer {
	return newCFListsEnforcerForTestWithCtx(context.Background(), token, baseURL, accountID, listName)
}

func newCFListsEnforcerForTestWithCtx(ctx context.Context, token, baseURL, accountID, listName string) *CloudflareListsEnforcer {
	if listName == "" {
		listName = cfDefaultListName
	}
	return &CloudflareListsEnforcer{
		client:           &http.Client{Timeout: 5 * time.Second},
		token:            token,
		accountID:        accountID,
		listName:         listName,
		baseURL:          baseURL,
		limiter:          newCFRateLimiter(1000), // effectively no throttle in tests
		debounceInterval: 0,
		svcCtx:           ctx,
		state:            newListState(),
	}
}

// Name implements sdk.Enforcer.
func (e *CloudflareListsEnforcer) Name() string { return "cloudflare" }

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
// untouched.
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
		flushCtx, cancel := context.WithTimeout(e.svcCtx, 30*time.Second)
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
	e.state.mu.Unlock()

	if needsDiscover {
		newID, newItems, err := e.discoverList(ctx)
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
		}
		e.state.mu.Lock()
		e.state.discovered = true
		e.state.listID = newID
		e.state.items = newItems
		listID = newID
		itemsCopy = make(map[string]string, len(newItems))
		for ip, id := range newItems {
			itemsCopy[ip] = id
		}
		e.state.mu.Unlock()
	}

	// Compute the diff: anything desired that we don't manage yet → add.
	// Anything we manage but is no longer desired → remove.
	var toAdd []string
	for ip := range desiredCopy {
		if _, ok := itemsCopy[ip]; !ok {
			toAdd = append(toAdd, ip)
		}
	}
	var toRemoveIPs []string
	var toRemoveIDs []string
	for ip, id := range itemsCopy {
		if _, ok := desiredCopy[ip]; !ok {
			toRemoveIPs = append(toRemoveIPs, ip)
			toRemoveIDs = append(toRemoveIDs, id)
		}
	}
	// Deterministic order so logs and tests are stable.
	sort.Strings(toAdd)

	if len(toAdd) > 0 {
		added, err := e.addItems(ctx, listID, toAdd)
		if err != nil {
			return err
		}
		e.state.mu.Lock()
		for ip, id := range added {
			e.state.items[ip] = id
		}
		e.state.mu.Unlock()
	}

	if len(toRemoveIDs) > 0 {
		if err := e.removeItems(ctx, listID, toRemoveIDs); err != nil {
			return err
		}
		e.state.mu.Lock()
		for _, ip := range toRemoveIPs {
			delete(e.state.items, ip)
		}
		e.state.mu.Unlock()
	}

	return nil
}

// ── CF Lists API discovery ────────────────────────────────────────────────────

// discoverList finds the configured list by name in the account and returns
// (listID, ezyshield-managed items, nil). When the list is missing, returns
// ("", nil, nil) so the caller can create it.
func (e *CloudflareListsEnforcer) discoverList(ctx context.Context) (string, map[string]string, error) {
	if err := e.limiter.wait(ctx); err != nil {
		return "", nil, err
	}
	url := fmt.Sprintf("%s/accounts/%s/rules/lists", e.baseURL, e.accountID)
	resp, err := e.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	var ls cfListListsResp
	if err := json.NewDecoder(resp.Body).Decode(&ls); err != nil {
		return "", nil, fmt.Errorf("decode list lists: %w", err)
	}
	if !ls.Success {
		return "", nil, fmt.Errorf("cloudflare list lists: %s", cfErrMsg(ls.Errors))
	}
	var listID string
	for _, l := range ls.Result {
		if l.Name == e.listName && l.Kind == "ip" {
			listID = l.ID
			break
		}
	}
	if listID == "" {
		return "", nil, nil
	}
	items, err := e.fetchAllItems(ctx, listID)
	if err != nil {
		return "", nil, err
	}
	return listID, items, nil
}

// fetchAllItems pages through every item in the list and returns the
// ezyshield-managed subset (comment starts with cfListItemTag). The page count
// is bounded to defend against a misbehaving API that returns an unmoving
// cursor — the free-plan cap is 10 000 items, so 50 pages of 1 000 is plenty.
func (e *CloudflareListsEnforcer) fetchAllItems(ctx context.Context, listID string) (map[string]string, error) {
	const maxPages = 50
	managed := make(map[string]string)
	cursor := ""
	for page := 0; page < maxPages; page++ {
		if err := e.limiter.wait(ctx); err != nil {
			return nil, err
		}
		url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items?per_page=%d",
			e.baseURL, e.accountID, listID, cfListItemPerPage)
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		resp, err := e.doRequest(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		var pg cfListItemsResp
		if err := json.NewDecoder(resp.Body).Decode(&pg); err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("decode list items: %w", err)
		}
		_ = resp.Body.Close()
		if !pg.Success {
			return nil, fmt.Errorf("cloudflare list items: %s", cfErrMsg(pg.Errors))
		}
		for _, it := range pg.Result {
			if !isManagedListItem(it.Comment) {
				continue
			}
			if it.IP != "" {
				managed[it.IP] = it.ID
			}
		}
		next := pg.ResultInfo.Cursors.After
		if next == "" || next == cursor {
			return managed, nil
		}
		cursor = next
	}
	return nil, fmt.Errorf("cloudflare list items: pagination exceeded %d pages", maxPages)
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

// addItems performs one bulk POST per Cloudflare batch limit and returns
// ip→itemID for the rows the API echoed back. When the API responds with an
// operation_id but no item bodies, addItems re-reads the list once to recover
// the IDs.
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
			payload[i] = cfListItemReq{IP: ip, Comment: cfListItemTag}
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal add items: %w", err)
		}
		if err := e.limiter.wait(ctx); err != nil {
			return nil, err
		}
		url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", e.baseURL, e.accountID, listID)
		resp, err := e.doRequest(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		var ar cfListAddResp
		if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("decode add items: %w", err)
		}
		_ = resp.Body.Close()
		if !ar.Success {
			return nil, fmt.Errorf("cloudflare add items: %s", cfErrMsg(ar.Errors))
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
		all, err := e.fetchAllItems(ctx, listID)
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
		if err := e.limiter.wait(ctx); err != nil {
			return err
		}
		url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", e.baseURL, e.accountID, listID)
		resp, err := e.doRequest(ctx, http.MethodDelete, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		var dr cfListDeleteResp
		if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
			_ = resp.Body.Close()
			return fmt.Errorf("decode delete items: %w", err)
		}
		_ = resp.Body.Close()
		if !dr.Success {
			return fmt.Errorf("cloudflare delete items: %s", cfErrMsg(dr.Errors))
		}
		slog.InfoContext(ctx, "enforce/cloudflare-lists: removed items",
			"count", len(batch), "list_id", listID)
	}
	return nil
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

// isManagedListItem returns true when the item's comment marks it as written by
// ezyshield. A bare "ezyshield" comment matches, as does any comment starting
// with "ezyshield" (so we can extend the tag in the future without breaking
// older deployments).
func isManagedListItem(comment string) bool {
	const tag = cfListItemTag
	if len(comment) < len(tag) {
		return false
	}
	return comment[:len(tag)] == tag
}

// ── Cloudflare Lists API wire types ──────────────────────────────────────────

type cfListInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
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

type cfListDeleteResp struct {
	Success bool         `json:"success"`
	Errors  []cfAPIError `json:"errors"`
}
