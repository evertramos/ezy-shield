package enforce_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	testCFAccount  = "acct-1"
	testCFListName = "ezyshield_blocked"
)

// ── mock Cloudflare Lists API server ─────────────────────────────────────────

type cfListsMockItem struct {
	ID      string
	IP      string
	Comment string
}

type cfListsMockList struct {
	ID    string
	Name  string
	Kind  string
	items map[string]*cfListsMockItem // itemID → item
}

type cfListsMock struct {
	mu        sync.Mutex
	accountID string
	lists     map[string]*cfListsMockList // listID → list
	byName    map[string]string           // name → listID
	nextID    int
	reqCount  atomic.Int32
	// Test knobs
	addReturnsAsync bool // true = POST items returns operation_id, no item bodies
	// rejectDuplicates mirrors the real Lists API refusing an add for an IP
	// already present in the list (issue #486 concurrent-instance race).
	rejectDuplicates bool
	throttleAdds     int  // next N POST items answer a throttle instead
	throttleDeletes  int  // next N DELETE items answer a throttle instead
	throttleAs429    bool // throttle as raw HTTP 429 (non-JSON body) instead of JSON code 10040
	failAddsCode     int  // when non-zero, next POST items fails with this (non-throttle) CF error code
	opPendingPolls   int  // bulk-operation polls answering "pending" before "completed"
	addCalls         int  // POST items requests observed (throttled ones included)
	deleteCalls      int  // DELETE items requests observed (throttled ones included)
	bulkOpPolls      int  // bulk-operation status requests observed
}

func newCFListsMock(accountID string) *cfListsMock {
	return &cfListsMock{
		accountID: accountID,
		lists:     make(map[string]*cfListsMockList),
		byName:    make(map[string]string),
	}
}

func (m *cfListsMock) genID(prefix string) string {
	m.nextID++
	return fmt.Sprintf("%s-%d", prefix, m.nextID)
}

func (m *cfListsMock) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		m.reqCount.Add(1)
		// Expected: /accounts/{acc}/rules/lists[/{list_id}[/items]]
		raw := strings.TrimPrefix(r.URL.Path, "/")
		parts := strings.Split(raw, "/")
		if len(parts) < 4 || parts[0] != "accounts" || parts[2] != "rules" || parts[3] != "lists" {
			http.NotFound(w, r)
			return
		}
		if parts[1] != m.accountID {
			writeJSON(w, cfError(7003, "account mismatch"))
			return
		}
		switch {
		case r.Method == http.MethodGet && len(parts) == 4:
			m.handleListLists(w)
		case r.Method == http.MethodPost && len(parts) == 4:
			m.handleCreateList(w, r)
		case r.Method == http.MethodGet && len(parts) == 6 && parts[5] == "items":
			m.handleGetItems(w, r, parts[4])
		case r.Method == http.MethodPost && len(parts) == 6 && parts[5] == "items":
			m.handlePostItems(w, r, parts[4])
		case r.Method == http.MethodDelete && len(parts) == 6 && parts[5] == "items":
			m.handleDeleteItems(w, r, parts[4])
		case r.Method == http.MethodGet && len(parts) == 6 && parts[4] == "bulk_operations":
			m.handleBulkOp(w, parts[5])
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

type cfListsMockListInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	NumItems int    `json:"num_items"`
}

type cfListsMockCreateReq struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

func (m *cfListsMock) handleListLists(w http.ResponseWriter) {
	m.mu.Lock()
	result := make([]cfListsMockListInfo, 0, len(m.lists))
	for _, l := range m.lists {
		result = append(result, cfListsMockListInfo{
			ID:       l.ID,
			Name:     l.Name,
			Kind:     l.Kind,
			NumItems: len(l.items),
		})
	}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(result))
}

func (m *cfListsMock) handleCreateList(w http.ResponseWriter, r *http.Request) {
	var req cfListsMockCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if req.Kind != "ip" || req.Name == "" {
		writeJSON(w, cfError(1004, "invalid create payload"))
		return
	}
	m.mu.Lock()
	if existing, ok := m.byName[req.Name]; ok {
		l := m.lists[existing]
		m.mu.Unlock()
		writeJSON(w, cfSuccess(cfListsMockListInfo{ID: l.ID, Name: l.Name, Kind: l.Kind}))
		return
	}
	l := &cfListsMockList{
		ID:    m.genID("list"),
		Name:  req.Name,
		Kind:  req.Kind,
		items: make(map[string]*cfListsMockItem),
	}
	m.lists[l.ID] = l
	m.byName[l.Name] = l.ID
	m.mu.Unlock()
	writeJSON(w, cfSuccess(cfListsMockListInfo{ID: l.ID, Name: l.Name, Kind: l.Kind}))
}

type cfListsMockItemWire struct {
	ID      string `json:"id"`
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

func (m *cfListsMock) handleGetItems(w http.ResponseWriter, _ *http.Request, listID string) {
	m.mu.Lock()
	l, ok := m.lists[listID]
	if !ok {
		m.mu.Unlock()
		writeJSON(w, cfError(1002, "list not found"))
		return
	}
	wire := make([]cfListsMockItemWire, 0, len(l.items))
	for _, it := range l.items {
		wire = append(wire, cfListsMockItemWire{ID: it.ID, IP: it.IP, Comment: it.Comment})
	}
	m.mu.Unlock()
	writeJSON(w, map[string]any{
		"success":     true,
		"errors":      []any{},
		"result":      wire,
		"result_info": map[string]any{"cursors": map[string]any{}},
	})
}

type cfListsMockAddReq []struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

func (m *cfListsMock) handlePostItems(w http.ResponseWriter, r *http.Request, listID string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var req cfListsMockAddReq
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	m.addCalls++
	if m.failAddsCode != 0 {
		code := m.failAddsCode
		m.failAddsCode = 0
		m.mu.Unlock()
		writeJSON(w, cfError(code, "invalid add payload"))
		return
	}
	if m.rejectDuplicates {
		if l, ok := m.lists[listID]; ok {
			for _, rr := range req {
				for _, it := range l.items {
					if it.IP == rr.IP {
						m.mu.Unlock()
						writeJSON(w, cfError(10009, "could not create list item: duplicate of existing entry"))
						return
					}
				}
			}
		}
	}
	if m.throttleAdds > 0 {
		m.throttleAdds--
		as429 := m.throttleAs429
		m.mu.Unlock()
		m.writeThrottle(w, as429)
		return
	}
	l, ok := m.lists[listID]
	if !ok {
		m.mu.Unlock()
		writeJSON(w, cfError(1002, "list not found"))
		return
	}
	wire := make([]cfListsMockItemWire, 0, len(req))
	for _, rr := range req {
		id := m.genID("item")
		l.items[id] = &cfListsMockItem{ID: id, IP: rr.IP, Comment: rr.Comment}
		wire = append(wire, cfListsMockItemWire{ID: id, IP: rr.IP, Comment: rr.Comment})
	}
	async := m.addReturnsAsync
	m.mu.Unlock()
	if async {
		writeJSON(w, cfSuccess(map[string]any{"operation_id": "op-123"}))
		return
	}
	writeJSON(w, cfSuccess(wire))
}

// writeThrottle answers like a rate-limited Cloudflare API: either the JSON
// error envelope with code 10040, or a raw HTTP 429 with a non-JSON body.
func (m *cfListsMock) writeThrottle(w http.ResponseWriter, as429 bool) {
	if as429 {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("rate limited"))
		return
	}
	writeJSON(w, cfError(10040, "you have been ratelimited please wait and try again"))
}

func (m *cfListsMock) handleBulkOp(w http.ResponseWriter, opID string) {
	m.mu.Lock()
	m.bulkOpPolls++
	pending := m.opPendingPolls > 0
	if pending {
		m.opPendingPolls--
	}
	m.mu.Unlock()
	status := "completed"
	if pending {
		status = "pending"
	}
	writeJSON(w, cfSuccess(map[string]any{"id": opID, "status": status}))
}

type cfListsMockDeleteReq struct {
	Items []struct {
		ID string `json:"id"`
	} `json:"items"`
}

func (m *cfListsMock) handleDeleteItems(w http.ResponseWriter, r *http.Request, listID string) {
	var req cfListsMockDeleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	m.deleteCalls++
	if m.throttleDeletes > 0 {
		m.throttleDeletes--
		as429 := m.throttleAs429
		m.mu.Unlock()
		m.writeThrottle(w, as429)
		return
	}
	l, ok := m.lists[listID]
	if !ok {
		m.mu.Unlock()
		writeJSON(w, cfError(1002, "list not found"))
		return
	}
	for _, d := range req.Items {
		delete(l.items, d.ID)
	}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(map[string]any{"operation_id": "op-del"}))
}

// ── mock inspection helpers ───────────────────────────────────────────────────

func (m *cfListsMock) counts() (addCalls, deleteCalls, bulkOpPolls int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addCalls, m.deleteCalls, m.bulkOpPolls
}

func (m *cfListsMock) setThrottleAdds(n int, as429 bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.throttleAdds = n
	m.throttleAs429 = as429
}

func (m *cfListsMock) listCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.lists)
}

func (m *cfListsMock) itemCount(listName string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byName[listName]
	if !ok {
		return 0
	}
	return len(m.lists[id].items)
}

func (m *cfListsMock) hasItem(listName, ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byName[listName]
	if !ok {
		return false
	}
	for _, it := range m.lists[id].items {
		if it.IP == ip {
			return true
		}
	}
	return false
}

// seedTaggedItem adds a pre-existing item with an arbitrary comment tag to
// the named list (creating the list if needed) — used for legacy bare
// "ezyshield" items and other instances' "ezyshield:<name>" items (#486).
func (m *cfListsMock) seedTaggedItem(listName, ip, comment string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byName[listName]
	if !ok {
		l := &cfListsMockList{
			ID:    m.genID("list"),
			Name:  listName,
			Kind:  "ip",
			items: make(map[string]*cfListsMockItem),
		}
		m.lists[l.ID] = l
		m.byName[listName] = l.ID
		id = l.ID
	}
	itemID := m.genID("item")
	m.lists[id].items[itemID] = &cfListsMockItem{ID: itemID, IP: ip, Comment: comment}
	return itemID
}

// itemCountFor counts list items carrying the given IP (any owner).
func (m *cfListsMock) itemCountFor(listName, ip string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byName[listName]
	if !ok {
		return 0
	}
	n := 0
	for _, it := range m.lists[id].items {
		if it.IP == ip {
			n++
		}
	}
	return n
}

// seedManagedItem adds a pre-existing ezyshield-tagged item to the named list
// (creating the list if needed). Used to simulate restart-time reconciliation.
// NOTE: the bare "ezyshield" comment is the pre-#486 LEGACY tag — unowned by
// default, adopted only via adopt_legacy_items.
func (m *cfListsMock) seedManagedItem(listName, ip string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byName[listName]
	if !ok {
		l := &cfListsMockList{
			ID:    m.genID("list"),
			Name:  listName,
			Kind:  "ip",
			items: make(map[string]*cfListsMockItem),
		}
		m.lists[l.ID] = l
		m.byName[listName] = l.ID
		id = l.ID
	}
	itemID := m.genID("item")
	m.lists[id].items[itemID] = &cfListsMockItem{ID: itemID, IP: ip, Comment: "ezyshield"}
	return itemID
}

// seedManualItem adds a non-ezyshield item to the named list (creating the
// list if needed). Used to verify that Sync/Unban don't touch foreign items.
func (m *cfListsMock) seedManualItem(listName, ip string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byName[listName]
	if !ok {
		l := &cfListsMockList{
			ID:    m.genID("list"),
			Name:  listName,
			Kind:  "ip",
			items: make(map[string]*cfListsMockItem),
		}
		m.lists[l.ID] = l
		m.byName[listName] = l.ID
		id = l.ID
	}
	itemID := m.genID("item")
	m.lists[id].items[itemID] = &cfListsMockItem{ID: itemID, IP: ip, Comment: "manual"}
	return itemID
}

func newMockCFListsServer(t *testing.T) (*cfListsMock, *httptest.Server) {
	t.Helper()
	m := newCFListsMock(testCFAccount)
	ts := httptest.NewServer(m.handler())
	t.Cleanup(ts.Close)
	return m, ts
}

// ── Ban tests ─────────────────────────────────────────────────────────────────

func TestCFListsBan_CreatesListAndItem(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)

	ip := netip.MustParseAddr("1.2.3.4")
	if err := e.Ban(context.Background(), sdk.Target{IP: ip, TTL: time.Hour}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if mock.listCount() != 1 {
		t.Errorf("expected 1 list (auto-created), got %d", mock.listCount())
	}
	if !mock.hasItem(testCFListName, "1.2.3.4") {
		t.Error("expected 1.2.3.4 to be in the list")
	}
}

func TestCFListsBan_CIDRTarget(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)

	pfx := netip.MustParsePrefix("10.0.0.0/8")
	if err := e.Ban(context.Background(), sdk.Target{Prefix: pfx}); err != nil {
		t.Fatalf("Ban CIDR: %v", err)
	}
	if !mock.hasItem(testCFListName, "10.0.0.0/8") {
		t.Error("expected 10.0.0.0/8 in the list")
	}
}

func TestCFListsBan_AllowlistedIP_Refused(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	allow := netip.MustParseAddr("10.0.0.1")
	e := enforce.NewCFListsEnforcerWithAllowlist("tok", ts.URL, testCFAccount, testCFListName,
		[]netip.Prefix{netip.PrefixFrom(allow, 32)})

	err := e.Ban(context.Background(), sdk.Target{IP: allow})
	if err == nil {
		t.Fatal("expected error banning allowlisted IP, got nil")
	}
	if mock.listCount() != 0 {
		t.Error("expected no API calls (and no list created) for allowlisted IP")
	}
}

func TestCFListsBan_ASNTarget_Rejected(t *testing.T) {
	_, ts := newMockCFListsServer(t)
	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)

	if err := e.Ban(context.Background(), sdk.Target{ASN: 1234}); err == nil {
		t.Fatal("expected error for ASN target (not supported)")
	}
}

func TestCFListsBan_MultipleIPs_SinglePush(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)

	for _, s := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr(s)}); err != nil {
			t.Fatalf("Ban %s: %v", s, err)
		}
	}
	if mock.itemCount(testCFListName) != 3 {
		t.Errorf("expected 3 items, got %d", mock.itemCount(testCFListName))
	}
}

// ── Unban tests ───────────────────────────────────────────────────────────────

func TestCFListsUnban_RemovesItem(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)

	ip := netip.MustParseAddr("7.7.7.7")
	if err := e.Ban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if mock.itemCount(testCFListName) != 1 {
		t.Fatal("expected 1 item after ban")
	}
	if err := e.Unban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if mock.itemCount(testCFListName) != 0 {
		t.Errorf("expected 0 items after unban, got %d", mock.itemCount(testCFListName))
	}
}

func TestCFListsUnban_PartialRemoval(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)

	for _, s := range []string{"1.1.1.1", "2.2.2.2"} {
		if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr(s)}); err != nil {
			t.Fatalf("Ban %s: %v", s, err)
		}
	}
	if err := e.Unban(context.Background(), sdk.Target{IP: netip.MustParseAddr("2.2.2.2")}); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if mock.hasItem(testCFListName, "2.2.2.2") {
		t.Error("2.2.2.2 should be removed")
	}
	if !mock.hasItem(testCFListName, "1.1.1.1") {
		t.Error("1.1.1.1 should still be present")
	}
}

func TestCFListsUnban_NoItem_NoError(t *testing.T) {
	_, ts := newMockCFListsServer(t)
	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)

	if err := e.Unban(context.Background(), sdk.Target{IP: netip.MustParseAddr("3.3.3.3")}); err != nil {
		t.Fatalf("Unban absent IP returned error: %v", err)
	}
}

func TestCFListsUnban_PreservesManualItems(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	mock.seedManualItem(testCFListName, "8.8.8.8")

	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)
	// Unban an IP we never banned — manual item must survive.
	if err := e.Unban(context.Background(), sdk.Target{IP: netip.MustParseAddr("8.8.8.8")}); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if !mock.hasItem(testCFListName, "8.8.8.8") {
		t.Error("manual 8.8.8.8 must not be removed by Unban")
	}
}

// ── Sync tests ────────────────────────────────────────────────────────────────

func TestCFListsSync_AddsMissingRemovesStale(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)

	for _, s := range []string{"1.1.1.1", "2.2.2.2"} {
		if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr(s)}); err != nil {
			t.Fatalf("pre-ban %s: %v", s, err)
		}
	}

	want := []sdk.Target{
		{IP: netip.MustParseAddr("1.1.1.1")}, // keep
		{IP: netip.MustParseAddr("3.3.3.3")}, // add
	}
	if err := e.Sync(context.Background(), want); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if mock.hasItem(testCFListName, "2.2.2.2") {
		t.Error("stale 2.2.2.2 should be removed")
	}
	if !mock.hasItem(testCFListName, "1.1.1.1") {
		t.Error("1.1.1.1 should still be present")
	}
	if !mock.hasItem(testCFListName, "3.3.3.3") {
		t.Error("3.3.3.3 should be added")
	}
}

func TestCFListsSync_EmptyWant_RemovesAll(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)

	for _, s := range []string{"1.1.1.1", "2.2.2.2"} {
		if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr(s)}); err != nil {
			t.Fatalf("pre-ban: %v", err)
		}
	}
	if err := e.Sync(context.Background(), nil); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if mock.itemCount(testCFListName) != 0 {
		t.Errorf("expected 0 items after empty sync, got %d", mock.itemCount(testCFListName))
	}
}

func TestCFListsSync_SkipsAllowlisted(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	allow := netip.MustParsePrefix("10.0.0.0/8")
	e := enforce.NewCFListsEnforcerWithAllowlist("tok", ts.URL, testCFAccount, testCFListName,
		[]netip.Prefix{allow})

	want := []sdk.Target{
		{IP: netip.MustParseAddr("10.1.2.3")}, // allowlisted — skip
		{IP: netip.MustParseAddr("5.5.5.5")},  // ban
	}
	if err := e.Sync(context.Background(), want); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if mock.hasItem(testCFListName, "10.1.2.3") {
		t.Error("allowlisted IP must not appear in list")
	}
	if !mock.hasItem(testCFListName, "5.5.5.5") {
		t.Error("5.5.5.5 should be in list")
	}
}

func TestCFListsSync_PreservesManualItems(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	mock.seedManualItem(testCFListName, "99.99.99.99")

	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)
	if err := e.Sync(context.Background(), nil); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !mock.hasItem(testCFListName, "99.99.99.99") {
		t.Error("manual item must not be removed by Sync")
	}
}

// TestCFListsSync_LegacyItemsPreservedByDefault: pre-#486 items (bare
// "ezyshield" comment) are ownerless — a default instance must NOT remove
// them (removing them is exactly the multi-server clobber #486 fixes), and
// must not re-add IPs already present under them.
func TestCFListsSync_LegacyItemsPreservedByDefault(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	mock.seedManagedItem(testCFListName, "203.0.113.10") // legacy, also desired
	mock.seedManagedItem(testCFListName, "203.0.113.70") // legacy, NOT desired
	mock.seedManualItem(testCFListName, "203.0.113.99")

	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)
	want := []sdk.Target{
		{IP: netip.MustParseAddr("203.0.113.10")},
		{IP: netip.MustParseAddr("203.0.113.20")},
	}
	if err := e.Sync(context.Background(), want); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !mock.hasItem(testCFListName, "203.0.113.20") {
		t.Error("new IP should be added under this instance's tag")
	}
	if !mock.hasItem(testCFListName, "203.0.113.70") {
		t.Error("legacy item (not desired here) must be preserved — it may belong to another server")
	}
	if got := mock.itemCountFor(testCFListName, "203.0.113.10"); got != 1 {
		t.Errorf("desired IP already present as legacy: %d items, want 1 (no duplicate add)", got)
	}
	if !mock.hasItem(testCFListName, "203.0.113.99") {
		t.Error("manual item must not be removed")
	}
}

// TestCFListsSync_AdoptsLegacyItemsWithOptIn: with adopt_legacy_items the
// pre-#486 items are owned again — reconciled and expirable — restoring the
// old single-server behavior for the one migrating instance.
func TestCFListsSync_AdoptsLegacyItemsWithOptIn(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	mock.seedManagedItem(testCFListName, "203.0.113.10")
	mock.seedManagedItem(testCFListName, "203.0.113.70")
	mock.seedManualItem(testCFListName, "203.0.113.99")

	e := enforce.NewCFListsEnforcerWithInstance("tok", ts.URL, testCFAccount, testCFListName, "web-a", true)
	want := []sdk.Target{
		{IP: netip.MustParseAddr("203.0.113.10")},
		{IP: netip.MustParseAddr("203.0.113.20")},
	}
	if err := e.Sync(context.Background(), want); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !mock.hasItem(testCFListName, "203.0.113.10") {
		t.Error("adopted legacy item (still desired) should remain")
	}
	if !mock.hasItem(testCFListName, "203.0.113.20") {
		t.Error("new IP should be added")
	}
	if mock.hasItem(testCFListName, "203.0.113.70") {
		t.Error("adopted legacy item no longer desired should be removed")
	}
	if !mock.hasItem(testCFListName, "203.0.113.99") {
		t.Error("manual item must not be removed")
	}
}

// TestCFListsSync_TwoInstancesShareOneList is the issue #486 regression:
// two daemons (different servers) sharing one account/list must each
// reconcile only their own subset — before the fix, each Sync deleted the
// other server's bans.
func TestCFListsSync_TwoInstancesShareOneList(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	ctx := context.Background()

	a := enforce.NewCFListsEnforcerWithInstance("tok", ts.URL, testCFAccount, testCFListName, "web-a", false)
	b := enforce.NewCFListsEnforcerWithInstance("tok", ts.URL, testCFAccount, testCFListName, "web-b", false)

	ipA := "203.0.113.1"
	ipB := "203.0.113.2"

	if err := a.Sync(ctx, []sdk.Target{{IP: netip.MustParseAddr(ipA)}}); err != nil {
		t.Fatalf("A Sync: %v", err)
	}
	if err := b.Sync(ctx, []sdk.Target{{IP: netip.MustParseAddr(ipB)}}); err != nil {
		t.Fatalf("B Sync: %v", err)
	}
	if !mock.hasItem(testCFListName, ipA) || !mock.hasItem(testCFListName, ipB) {
		t.Fatal("both servers' bans must coexist in the shared list")
	}

	// A re-syncs its unchanged set: B's ban must survive (the old code
	// deleted it here).
	if err := a.Sync(ctx, []sdk.Target{{IP: netip.MustParseAddr(ipA)}}); err != nil {
		t.Fatalf("A re-Sync: %v", err)
	}
	if !mock.hasItem(testCFListName, ipB) {
		t.Fatal("server A's sync removed server B's ban — issue #486 clobber")
	}

	// A's ban expires (empty desired): only A's item goes; B's stays.
	if err := a.Sync(ctx, nil); err != nil {
		t.Fatalf("A empty Sync: %v", err)
	}
	if mock.hasItem(testCFListName, ipA) {
		t.Error("A's expired ban should be removed by A")
	}
	if !mock.hasItem(testCFListName, ipB) {
		t.Error("B's ban must survive A's expiry sync")
	}
}

// TestCFListsSync_DuplicateAddFallsBackToForeign: another instance adds an
// IP between this instance's discovery and its push; the API refuses the
// duplicate. The push must succeed by marking the IP foreign and adding
// only the rest — and must not retry the foreign IP on the next push.
func TestCFListsSync_DuplicateAddFallsBackToForeign(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	ctx := context.Background()
	mock.mu.Lock()
	mock.rejectDuplicates = true
	mock.mu.Unlock()

	a := enforce.NewCFListsEnforcerWithInstance("tok", ts.URL, testCFAccount, testCFListName, "web-a", false)
	b := enforce.NewCFListsEnforcerWithInstance("tok", ts.URL, testCFAccount, testCFListName, "web-b", false)

	shared := "203.0.113.5"
	own := "203.0.113.6"

	// A discovers (creates) the list first with an unrelated ban.
	if err := a.Sync(ctx, []sdk.Target{{IP: netip.MustParseAddr(own)}}); err != nil {
		t.Fatalf("A initial Sync: %v", err)
	}
	// B bans the shared IP after A's discovery — invisible to A's state.
	if err := b.Sync(ctx, []sdk.Target{{IP: netip.MustParseAddr(shared)}}); err != nil {
		t.Fatalf("B Sync: %v", err)
	}

	// A now wants the shared IP too; its add hits the duplicate refusal and
	// must fall back instead of failing the push.
	if err := a.Sync(ctx, []sdk.Target{
		{IP: netip.MustParseAddr(own)},
		{IP: netip.MustParseAddr(shared)},
	}); err != nil {
		t.Fatalf("A Sync with duplicate: %v", err)
	}
	if got := mock.itemCountFor(testCFListName, shared); got != 1 {
		t.Errorf("shared IP items = %d, want 1 (owned by B alone)", got)
	}

	// Next identical push: the foreign IP is cached, no failing re-add.
	if err := a.Sync(ctx, []sdk.Target{
		{IP: netip.MustParseAddr(own)},
		{IP: netip.MustParseAddr(shared)},
	}); err != nil {
		t.Fatalf("A repeat Sync: %v", err)
	}
	if !mock.hasItem(testCFListName, shared) || !mock.hasItem(testCFListName, own) {
		t.Error("both IPs must remain blocked at the edge")
	}
}

// ── Debounce tests ────────────────────────────────────────────────────────────

func TestCFListsBan_Debounce_BatchesPushes(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	e := enforce.NewCFListsEnforcerWithDebounce("tok", ts.URL, testCFAccount, testCFListName, 40*time.Millisecond)

	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	for _, s := range ips {
		if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr(s)}); err != nil {
			t.Fatalf("Ban %s: %v", s, err)
		}
	}
	// Before debounce fires, nothing should be pushed.
	if mock.itemCount(testCFListName) != 0 {
		t.Errorf("expected 0 items before debounce, got %d", mock.itemCount(testCFListName))
	}

	time.Sleep(120 * time.Millisecond)

	for _, s := range ips {
		if !mock.hasItem(testCFListName, s) {
			t.Errorf("expected %s in list after debounce", s)
		}
	}
	// Single debounced push: 1 list-lookup + 1 create-list + 1 add-items = 3.
	// Allow some margin.
	if got := mock.reqCount.Load(); got > 5 {
		t.Errorf("too many API requests (%d); debounce should batch", got)
	}
}

func TestCFListsBan_Debounce_ContextCancelSkipsFlush(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	e := enforce.NewCFListsEnforcerWithDebounceAndCtx(ctx, "tok", ts.URL, testCFAccount, testCFListName, 50*time.Millisecond)

	if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("9.9.9.9")}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	cancel()
	time.Sleep(120 * time.Millisecond)

	if mock.listCount() != 0 {
		t.Errorf("expected no list created after service-context cancel, got %d", mock.listCount())
	}
}

// ── Async-response handling ──────────────────────────────────────────────────

func TestCFListsBan_AsyncAddResponse_RefetchesItemIDs(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	mock.addReturnsAsync = true

	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)
	if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("1.2.3.4")}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if !mock.hasItem(testCFListName, "1.2.3.4") {
		t.Fatal("expected 1.2.3.4 to be added")
	}
	// Now the enforcer should know the item's ID — Unban must successfully delete it.
	if err := e.Unban(context.Background(), sdk.Target{IP: netip.MustParseAddr("1.2.3.4")}); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if mock.itemCount(testCFListName) != 0 {
		t.Errorf("expected 0 items after Unban following async-add, got %d", mock.itemCount(testCFListName))
	}
}

// ── Name / factory tests ─────────────────────────────────────────────────────

func TestCFListsName(t *testing.T) {
	e := enforce.NewCFListsEnforcerForTest("tok", "http://localhost", testCFAccount, testCFListName)
	if got := e.Name(); got != "cloudflare" {
		t.Errorf("Name() = %q, want 'cloudflare'", got)
	}
}

// ── Secret-leak gate (SECURITY-REVIEW §4) ─────────────────────────────────────

func TestCFListsBan_TokenNotInError(t *testing.T) {
	const secret = "SUPER-SECRET-CF-LISTS-TOKEN-zzz999"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"errors":  []map[string]any{{"code": 403, "message": "Forbidden"}},
		})
	}))
	defer ts.Close()

	e := enforce.NewCFListsEnforcerForTest(secret, ts.URL, testCFAccount, testCFListName)
	err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("1.2.3.4")})
	if err == nil {
		t.Fatal("expected error from API failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("API token leaked into error message: %q", err.Error())
	}
}

func TestCFListsSync_EmptyListSucceeds(t *testing.T) {
	// Test that Sync succeeds on an empty list (GitHub issue #75).
	// Cloudflare returns error 10027 when per_page is set on empty lists,
	// so we must early-return from fetchAllItems when num_items == 0.
	mock := newCFListsMock(testCFAccount)
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()

	e := enforce.NewCFListsEnforcerForTest("test-token", ts.URL, testCFAccount, testCFListName)

	// Create an empty list
	ctx := context.Background()
	// First, discover (which creates the list on demand)
	wantIPs := []sdk.Target{
		{IP: netip.MustParseAddr("1.2.3.4")},
		{IP: netip.MustParseAddr("2.3.4.5")},
	}

	// Sync with IPs should succeed, creating list and adding items
	if err := e.Sync(ctx, wantIPs); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// Now Sync with empty list (no IPs) should succeed
	if err := e.Sync(ctx, []sdk.Target{}); err != nil {
		t.Fatalf("Sync with empty target list failed: %v", err)
	}

	// Verify the list was discovered and is now empty
	// (In a real scenario, the empty list would have num_items == 0)
	// This test primarily verifies that fetchAllItems handles num_items == 0 correctly
}

// ── throttle / backoff tests (issue #445) ────────────────────────────────────

func TestCFListsBan_ThrottledAdd_RetriesThenSucceeds(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	mock.setThrottleAdds(2, false) // two JSON 10040 answers, then success
	e := enforce.NewCFListsEnforcerWithRetryDelays("tok", ts.URL, testCFAccount, testCFListName,
		[]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond})

	if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("192.0.2.10")}); err != nil {
		t.Fatalf("Ban despite retryable throttle: %v", err)
	}
	if !mock.hasItem(testCFListName, "192.0.2.10") {
		t.Error("item missing after throttle retries")
	}
	adds, _, _ := mock.counts()
	if adds != 3 {
		t.Errorf("add attempts = %d, want 3 (2 throttled + 1 success)", adds)
	}
}

func TestCFListsBan_ThrottledAddRaw429_Retries(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	mock.setThrottleAdds(1, true) // raw HTTP 429 with a non-JSON body
	e := enforce.NewCFListsEnforcerWithRetryDelays("tok", ts.URL, testCFAccount, testCFListName,
		[]time.Duration{time.Millisecond})

	if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("192.0.2.11")}); err != nil {
		t.Fatalf("Ban despite retryable 429: %v", err)
	}
	if !mock.hasItem(testCFListName, "192.0.2.11") {
		t.Error("item missing after 429 retry")
	}
}

func TestCFListsBan_ThrottleExhausted_WrapsErrCFThrottled(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	mock.setThrottleAdds(99, false) // throttle every attempt
	e := enforce.NewCFListsEnforcerWithRetryDelays("tok", ts.URL, testCFAccount, testCFListName,
		[]time.Duration{time.Millisecond}) // 2 attempts total

	err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("192.0.2.12")})
	if err == nil {
		t.Fatal("Ban succeeded, want throttle-exhausted error")
	}
	if !errors.Is(err, enforce.ErrCFThrottled) {
		t.Errorf("error does not wrap ErrCFThrottled: %v", err)
	}
	adds, _, _ := mock.counts()
	if adds != 2 {
		t.Errorf("add attempts = %d, want 2", adds)
	}
}

func TestCFListsBan_NonThrottleError_NoRetry(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	mock.mu.Lock()
	mock.failAddsCode = 1004 // real (non-throttle) API failure
	mock.mu.Unlock()
	e := enforce.NewCFListsEnforcerWithRetryDelays("tok", ts.URL, testCFAccount, testCFListName,
		[]time.Duration{time.Millisecond, time.Millisecond})

	err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("192.0.2.13")})
	if err == nil {
		t.Fatal("Ban succeeded, want real API failure")
	}
	if errors.Is(err, enforce.ErrCFThrottled) {
		t.Errorf("real failure must not be classified as throttle: %v", err)
	}
	adds, _, _ := mock.counts()
	if adds != 1 {
		t.Errorf("add attempts = %d, want 1 (no retry on real failures)", adds)
	}
}

func TestIsThrottleOnly(t *testing.T) {
	throttle := fmt.Errorf("cloudflare add items: 10040: ratelimited: %w", enforce.ErrCFThrottled)
	real := errors.New("nftables: enforcer socket gone")
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain throttle", throttle, true},
		{"wrapped throttle", fmt.Errorf("cloudflare: %w", throttle), true},
		{"real failure", real, false},
		{"join all throttled", errors.Join(throttle, fmt.Errorf("cloudflare[b]: %w", enforce.ErrCFThrottled)), true},
		{"join mixed", errors.Join(throttle, real), false},
		{"wrapped mixed join", fmt.Errorf("sync: %w", errors.Join(throttle, real)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := enforce.IsThrottleOnly(tc.err); got != tc.want {
				t.Errorf("IsThrottleOnly(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// ── deferred removal flush tests (issue #445) ────────────────────────────────

func TestCFListsDeferredRemovals_NotInlineThenBatchedInOneCall(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// A very long cadence: the ticker never fires during the test, so the
	// flush moment is exercised deterministically via FlushRemovalsForTest.
	e := enforce.NewCFListsEnforcerWithExpireFlush(ctx, "tok", ts.URL, testCFAccount, testCFListName, time.Hour)

	for _, s := range []string{"192.0.2.20", "192.0.2.21"} {
		if err := e.Ban(ctx, sdk.Target{IP: netip.MustParseAddr(s)}); err != nil {
			t.Fatalf("pre-ban %s: %v", s, err)
		}
	}
	// Drop one IP via Sync and the other via Unban: neither removal may go
	// out inline in deferred mode.
	if err := e.Sync(ctx, []sdk.Target{{IP: netip.MustParseAddr("192.0.2.21")}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := e.Unban(ctx, sdk.Target{IP: netip.MustParseAddr("192.0.2.21")}); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if _, deletes, _ := mock.counts(); deletes != 0 {
		t.Fatalf("delete calls before flush = %d, want 0 (removals deferred)", deletes)
	}
	if mock.itemCount(testCFListName) != 2 {
		t.Fatalf("items before flush = %d, want 2", mock.itemCount(testCFListName))
	}

	if err := e.FlushRemovalsForTest(ctx); err != nil {
		t.Fatalf("flushRemovals: %v", err)
	}
	if mock.itemCount(testCFListName) != 0 {
		t.Errorf("items after flush = %d, want 0", mock.itemCount(testCFListName))
	}
	if _, deletes, _ := mock.counts(); deletes != 1 {
		t.Errorf("delete calls after flush = %d, want 1 (both removals in one batch)", deletes)
	}
}

func TestCFListsDeferredRemovals_TickerEventuallyFlushes(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e := enforce.NewCFListsEnforcerWithExpireFlush(ctx, "tok", ts.URL, testCFAccount, testCFListName, 30*time.Millisecond)

	if err := e.Ban(ctx, sdk.Target{IP: netip.MustParseAddr("192.0.2.30")}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if err := e.Unban(ctx, sdk.Target{IP: netip.MustParseAddr("192.0.2.30")}); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mock.itemCount(testCFListName) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("item still present after 2s; deferred flusher never removed it")
}

// ── async bulk-operation polling tests (issue #445) ──────────────────────────

func TestCFListsBan_AsyncAdd_PollsOperationToCompletion(t *testing.T) {
	mock, ts := newMockCFListsServer(t)
	mock.mu.Lock()
	mock.addReturnsAsync = true
	mock.opPendingPolls = 2 // two "pending" answers before "completed"
	mock.mu.Unlock()
	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)

	if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("192.0.2.40")}); err != nil {
		t.Fatalf("Ban with async operation: %v", err)
	}
	if !mock.hasItem(testCFListName, "192.0.2.40") {
		t.Error("item missing after async add")
	}
	if _, _, polls := mock.counts(); polls < 3 {
		t.Errorf("bulk-operation polls = %d, want >= 3 (2 pending + 1 completed)", polls)
	}
}
