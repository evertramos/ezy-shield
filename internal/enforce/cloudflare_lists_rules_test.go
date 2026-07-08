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
	"testing"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// ── mock Cloudflare API for lists mode with zone rules ──────────────────────

type cfListsWithRulesMockRuleset struct {
	ID    string
	Phase string
	Rules map[string]*cfMockRule // ruleID → rule
}

type cfListsWithRulesMock struct {
	mu        sync.Mutex
	accountID string
	lists     map[string]*cfListsMockList // listID → list
	byName    map[string]string           // name → listID
	zones     map[string]*cfListsWithRulesMockRuleset
	nextID    int
}

func newCFListsWithRulesMock(accountID string) *cfListsWithRulesMock {
	return &cfListsWithRulesMock{
		accountID: accountID,
		lists:     make(map[string]*cfListsMockList),
		byName:    make(map[string]string),
		zones:     make(map[string]*cfListsWithRulesMockRuleset),
	}
}

func (m *cfListsWithRulesMock) genID(prefix string) string {
	m.nextID++
	return fmt.Sprintf("%s-%d", prefix, m.nextID)
}

func (m *cfListsWithRulesMock) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.URL.Path, "/")
		parts := strings.Split(raw, "/")

		// Lists API endpoints
		if len(parts) >= 4 && parts[0] == "accounts" && parts[2] == "rules" && parts[3] == "lists" {
			if parts[1] != m.accountID {
				writeJSON(w, cfError(7003, "account mismatch"))
				return
			}
			m.handleListsAPI(w, r, parts)
			return
		}

		// Rulesets API endpoints (for WAF rule management)
		if len(parts) >= 3 && parts[0] == "zones" && parts[2] == "rulesets" {
			zone := parts[1]
			m.handleRulesetsAPI(w, r, zone, parts)
			return
		}

		http.NotFound(w, r)
	})
	return mux
}

func (m *cfListsWithRulesMock) handleListsAPI(w http.ResponseWriter, r *http.Request, parts []string) {
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
}

func (m *cfListsWithRulesMock) handleRulesetsAPI(w http.ResponseWriter, r *http.Request, zone string, parts []string) {
	switch {
	case r.Method == http.MethodGet && len(parts) == 3:
		m.handleListRulesets(w, zone)
	case r.Method == http.MethodPost && len(parts) == 3:
		m.handleCreateRuleset(w, r, zone)
	case r.Method == http.MethodGet && len(parts) == 4:
		m.handleGetRuleset(w, zone, parts[3])
	case r.Method == http.MethodPost && len(parts) == 5 && parts[4] == "rules":
		m.handleCreateRule(w, r, zone, parts[3])
	case r.Method == http.MethodPatch && len(parts) == 6 && parts[4] == "rules":
		m.handlePatchRule(w, r, zone, parts[3], parts[5])
	default:
		http.NotFound(w, r)
	}
}

func (m *cfListsWithRulesMock) handleListLists(w http.ResponseWriter) {
	m.mu.Lock()
	result := make([]cfListsMockListInfo, 0, len(m.lists))
	for _, l := range m.lists {
		result = append(result, cfListsMockListInfo{ID: l.ID, Name: l.Name, Kind: l.Kind})
	}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(result))
}

func (m *cfListsWithRulesMock) handleCreateList(w http.ResponseWriter, r *http.Request) {
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

func (m *cfListsWithRulesMock) handleGetItems(w http.ResponseWriter, _ *http.Request, listID string) {
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

func (m *cfListsWithRulesMock) handlePostItems(w http.ResponseWriter, r *http.Request, listID string) {
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
	m.mu.Unlock()
	writeJSON(w, cfSuccess(map[string]any{"items": wire}))
}

func (m *cfListsWithRulesMock) handleDeleteItems(w http.ResponseWriter, r *http.Request, listID string) {
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
	for _, item := range req.Items {
		delete(l.items, item.ID)
	}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(map[string]any{}))
}

func (m *cfListsWithRulesMock) handleListRulesets(w http.ResponseWriter, zone string) {
	m.mu.Lock()
	z, ok := m.zones[zone]
	var result []cfMockRulesetInfo
	if ok && z.ID != "" {
		result = []cfMockRulesetInfo{{ID: z.ID, Phase: "http_request_firewall_custom"}}
	}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(result))
}

func (m *cfListsWithRulesMock) handleCreateRuleset(w http.ResponseWriter, r *http.Request, zone string) {
	var req cfMockCreateRulesetReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	if _, ok := m.zones[zone]; !ok {
		m.zones[zone] = &cfListsWithRulesMockRuleset{Rules: make(map[string]*cfMockRule)}
	}
	z := m.zones[zone]
	z.ID = m.genID("ruleset")
	z.Phase = req.Phase
	var wireRules []cfMockWireRule
	for _, rr := range req.Rules {
		id := m.genID("rule")
		z.Rules[id] = &cfMockRule{ID: id, Action: rr.Action, Expression: rr.Expression, Description: rr.Description}
		wireRules = append(wireRules, cfMockWireRule{ID: id, Action: rr.Action, Expression: rr.Expression, Description: rr.Description})
	}
	detail := cfMockRulesetDetail{ID: z.ID, Phase: z.Phase, Rules: wireRules}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(detail))
}

func (m *cfListsWithRulesMock) handleGetRuleset(w http.ResponseWriter, zone, rulesetID string) {
	m.mu.Lock()
	z, ok := m.zones[zone]
	if !ok || z.ID != rulesetID {
		m.mu.Unlock()
		writeJSON(w, cfError(1002, "ruleset not found"))
		return
	}
	var wireRules []cfMockWireRule
	for _, r := range z.Rules {
		wireRules = append(wireRules, cfMockWireRule{ID: r.ID, Action: r.Action, Expression: r.Expression, Description: r.Description})
	}
	detail := cfMockRulesetDetail{ID: rulesetID, Phase: z.Phase, Rules: wireRules}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(detail))
}

func (m *cfListsWithRulesMock) handleCreateRule(w http.ResponseWriter, r *http.Request, zone, rulesetID string) {
	var req cfMockRuleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	z, ok := m.zones[zone]
	if !ok || z.ID != rulesetID {
		m.mu.Unlock()
		writeJSON(w, cfError(1002, "ruleset not found"))
		return
	}
	id := m.genID("rule")
	rule := &cfMockRule{ID: id, Action: req.Action, Expression: req.Expression, Description: req.Description}
	z.Rules[id] = rule
	wire := cfMockWireRule{ID: id, Action: rule.Action, Expression: rule.Expression, Description: rule.Description}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(wire))
}

func (m *cfListsWithRulesMock) handlePatchRule(w http.ResponseWriter, r *http.Request, zone, rulesetID, ruleID string) {
	var req cfMockRuleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	z, ok := m.zones[zone]
	if !ok || z.ID != rulesetID {
		m.mu.Unlock()
		writeJSON(w, cfError(1002, "ruleset not found"))
		return
	}
	rule, ok := z.Rules[ruleID]
	if !ok {
		m.mu.Unlock()
		writeJSON(w, cfError(1002, "rule not found"))
		return
	}
	if req.Action != "" {
		rule.Action = req.Action
	}
	if req.Expression != "" {
		rule.Expression = req.Expression
	}
	if req.Description != "" {
		rule.Description = req.Description
	}
	wire := cfMockWireRule{ID: ruleID, Action: rule.Action, Expression: rule.Expression, Description: rule.Description}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(wire))
}

func newMockCFListsWithRulesServer(t *testing.T) (*cfListsWithRulesMock, *httptest.Server) {
	t.Helper()
	mock := newCFListsWithRulesMock(testCFAccount)
	ts := httptest.NewServer(mock.handler())
	t.Cleanup(ts.Close)
	return mock, ts
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestCFListsWithRules_SyncCreatesWAFRule(t *testing.T) {
	mock, ts := newMockCFListsWithRulesServer(t)
	zone := "zone-1"
	e := enforce.NewCFListsEnforcerForTestWithZones(context.Background(), "tok", ts.URL, testCFAccount, testCFListName, []string{zone})

	ip := netip.MustParseAddr("1.2.3.4")
	if err := e.Sync(context.Background(), []sdk.Target{{IP: ip}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Check that the list was created.
	mock.mu.Lock()
	if len(mock.lists) == 0 {
		t.Error("expected list to be created")
	}

	// Check that the WAF rule was created for the zone.
	z, zoneExists := mock.zones[zone]
	if !zoneExists {
		t.Error("expected zone to be created")
	}
	if len(z.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(z.Rules))
	}
	mock.mu.Unlock()
}

func TestCFListsWithRules_RuleExpressionUsesListID(t *testing.T) {
	mock, ts := newMockCFListsWithRulesServer(t)
	zone := "zone-1"
	e := enforce.NewCFListsEnforcerForTestWithZones(context.Background(), "tok", ts.URL, testCFAccount, testCFListName, []string{zone})

	ip := netip.MustParseAddr("5.6.7.8")
	if err := e.Sync(context.Background(), []sdk.Target{{IP: ip}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	mock.mu.Lock()
	z := mock.zones[zone]
	if len(z.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(z.Rules))
	}

	var rule *cfMockRule
	for _, r := range z.Rules {
		rule = r
		break
	}

	// Find the list ID that was created.
	var listID string
	for _, l := range mock.lists {
		if l.Name == testCFListName {
			listID = l.ID
			break
		}
	}
	mock.mu.Unlock()

	if listID == "" {
		t.Fatal("expected list to be created")
	}

	expectedExpr := fmt.Sprintf("(ip.src in $%s)", listID)
	if rule.Expression != expectedExpr {
		t.Errorf("rule expression = %q, want %q", rule.Expression, expectedExpr)
	}
}

func TestCFListsWithRules_Idempotent(t *testing.T) {
	mock, ts := newMockCFListsWithRulesServer(t)
	zone := "zone-1"
	e := enforce.NewCFListsEnforcerForTestWithZones(context.Background(), "tok", ts.URL, testCFAccount, testCFListName, []string{zone})

	ip := netip.MustParseAddr("9.9.9.9")
	if err := e.Sync(context.Background(), []sdk.Target{{IP: ip}}); err != nil {
		t.Fatalf("first Sync: %v", err)
	}

	mock.mu.Lock()
	initialRuleCount := len(mock.zones[zone].Rules)
	var initialRuleID string
	for id := range mock.zones[zone].Rules {
		initialRuleID = id
		break
	}
	mock.mu.Unlock()

	// Sync again with the same target; should not create a new rule.
	if err := e.Sync(context.Background(), []sdk.Target{{IP: ip}}); err != nil {
		t.Fatalf("second Sync: %v", err)
	}

	mock.mu.Lock()
	finalRuleCount := len(mock.zones[zone].Rules)
	var finalRuleID string
	for id := range mock.zones[zone].Rules {
		finalRuleID = id
		break
	}
	mock.mu.Unlock()

	if finalRuleCount != initialRuleCount {
		t.Errorf("rule count changed: %d → %d (expected idempotent)", initialRuleCount, finalRuleCount)
	}
	if finalRuleID != initialRuleID {
		t.Error("rule ID changed (expected idempotent)")
	}
}

func TestCFListsWithRules_MultiZone(t *testing.T) {
	mock, ts := newMockCFListsWithRulesServer(t)
	zones := []string{"zone-1", "zone-2", "zone-3"}
	e := enforce.NewCFListsEnforcerForTestWithZones(context.Background(), "tok", ts.URL, testCFAccount, testCFListName, zones)

	ip := netip.MustParseAddr("10.11.12.13")
	if err := e.Sync(context.Background(), []sdk.Target{{IP: ip}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	mock.mu.Lock()
	for _, zone := range zones {
		z, ok := mock.zones[zone]
		if !ok {
			t.Errorf("zone %s not created", zone)
			continue
		}
		if len(z.Rules) != 1 {
			t.Errorf("zone %s: expected 1 rule, got %d", zone, len(z.Rules))
		}
	}
	mock.mu.Unlock()
}

func TestCFListsWithRules_ActionConfiguration(t *testing.T) {
	// Note: This test uses the internal test constructor to set the action.
	// In real usage, the action is set from config.CloudflareCfg.
	mock, ts := newMockCFListsWithRulesServer(t)
	zone := "zone-1"
	e := enforce.NewCFListsEnforcerForTestWithZones(context.Background(), "tok", ts.URL, testCFAccount, testCFListName, []string{zone})

	ip := netip.MustParseAddr("14.15.16.17")
	if err := e.Sync(context.Background(), []sdk.Target{{IP: ip}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	mock.mu.Lock()
	z := mock.zones[zone]
	if len(z.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(z.Rules))
	}
	var rule *cfMockRule
	for _, r := range z.Rules {
		rule = r
		break
	}
	mock.mu.Unlock()

	if rule.Action != "block" {
		t.Errorf("rule action = %q, want %q", rule.Action, "block")
	}
}

func TestCFListsWithRules_RuleDescription(t *testing.T) {
	mock, ts := newMockCFListsWithRulesServer(t)
	zone := "zone-1"
	e := enforce.NewCFListsEnforcerForTestWithZones(context.Background(), "tok", ts.URL, testCFAccount, testCFListName, []string{zone})

	ip := netip.MustParseAddr("18.19.20.21")
	if err := e.Sync(context.Background(), []sdk.Target{{IP: ip}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	mock.mu.Lock()
	z := mock.zones[zone]
	if len(z.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(z.Rules))
	}
	var rule *cfMockRule
	for _, r := range z.Rules {
		rule = r
		break
	}
	mock.mu.Unlock()

	if !strings.Contains(rule.Description, "ezyshield-list-block") {
		t.Errorf("rule description = %q, expected to contain %q", rule.Description, "ezyshield-list-block")
	}
}

func TestCFListsWithRules_NoZones_ListsOnlyMode(t *testing.T) {
	mock, ts := newMockCFListsWithRulesServer(t)
	// Create enforcer without zones
	e := enforce.NewCFListsEnforcerForTestWithZones(context.Background(), "tok", ts.URL, testCFAccount, testCFListName, nil)

	ip := netip.MustParseAddr("22.23.24.25")
	if err := e.Sync(context.Background(), []sdk.Target{{IP: ip}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// List should be created, but no WAF rules.
	mock.mu.Lock()
	if len(mock.lists) != 1 {
		t.Errorf("expected 1 list, got %d", len(mock.lists))
	}
	if len(mock.zones) != 0 {
		t.Errorf("expected no zones, got %d", len(mock.zones))
	}
	mock.mu.Unlock()
}
