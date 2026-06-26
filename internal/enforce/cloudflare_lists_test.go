package enforce_test

import (
	"context"
	"encoding/json"
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
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

type cfListsMockListInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
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
		result = append(result, cfListsMockListInfo{ID: l.ID, Name: l.Name, Kind: l.Kind})
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

// seedManagedItem adds a pre-existing ezyshield-tagged item to the named list
// (creating the list if needed). Used to simulate restart-time reconciliation.
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

func TestCFListsSync_AdoptsPreExistingManagedItems(t *testing.T) {
	// Simulate daemon restart: list and managed item already exist from a
	// prior run. Sync should reconcile (1.1.1.1 stays, 2.2.2.2 added,
	// 7.7.7.7 removed, manual 99 untouched).
	mock, ts := newMockCFListsServer(t)
	mock.seedManagedItem(testCFListName, "1.1.1.1")
	mock.seedManagedItem(testCFListName, "7.7.7.7")
	mock.seedManualItem(testCFListName, "99.99.99.99")

	e := enforce.NewCFListsEnforcerForTest("tok", ts.URL, testCFAccount, testCFListName)
	want := []sdk.Target{
		{IP: netip.MustParseAddr("1.1.1.1")},
		{IP: netip.MustParseAddr("2.2.2.2")},
	}
	if err := e.Sync(context.Background(), want); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !mock.hasItem(testCFListName, "1.1.1.1") {
		t.Error("1.1.1.1 (pre-existing managed) should remain")
	}
	if !mock.hasItem(testCFListName, "2.2.2.2") {
		t.Error("2.2.2.2 (new) should be added")
	}
	if mock.hasItem(testCFListName, "7.7.7.7") {
		t.Error("7.7.7.7 (managed, no longer desired) should be removed")
	}
	if !mock.hasItem(testCFListName, "99.99.99.99") {
		t.Error("manual item must not be removed")
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
