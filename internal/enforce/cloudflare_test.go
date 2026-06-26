package enforce_test

import (
	"context"
	"encoding/json"
	"fmt"
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

// ── mock Cloudflare Rulesets API server ──────────────────────────────────────

type cfMockRule struct {
	ID          string
	Action      string
	Expression  string
	Description string
}

type cfMockZone struct {
	rulesetID string // empty until a ruleset is created
	rules     map[string]*cfMockRule
}

type cfMock struct {
	mu       sync.Mutex
	zones    map[string]*cfMockZone
	nextID   int
	reqCount atomic.Int32
}

func newCFMock() *cfMock {
	return &cfMock{zones: make(map[string]*cfMockZone)}
}

// zoneNoLock returns (creating if needed) the zone state. Must be called with m.mu held.
func (m *cfMock) zoneNoLock(zone string) *cfMockZone {
	if z, ok := m.zones[zone]; ok {
		return z
	}
	z := &cfMockZone{rules: make(map[string]*cfMockRule)}
	m.zones[zone] = z
	return z
}

func (m *cfMock) genID() string {
	m.nextID++
	return fmt.Sprintf("id-%d", m.nextID)
}

// handler returns an http.Handler for the mock Rulesets API.
func (m *cfMock) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		m.reqCount.Add(1)
		// Path: /zones/{zone}/rulesets[/{rulesetID}[/rules[/{ruleID}]]]
		raw := strings.TrimPrefix(r.URL.Path, "/")
		parts := strings.Split(raw, "/")
		// Minimum: ["zones", zone, "rulesets"] = 3 parts
		if len(parts) < 3 || parts[0] != "zones" || parts[2] != "rulesets" {
			http.NotFound(w, r)
			return
		}
		zone := parts[1]
		switch {
		// GET /zones/{zone}/rulesets
		case r.Method == http.MethodGet && len(parts) == 3:
			m.handleListRulesets(w, zone)
		// POST /zones/{zone}/rulesets
		case r.Method == http.MethodPost && len(parts) == 3:
			m.handleCreateRuleset(w, r, zone)
		// GET /zones/{zone}/rulesets/{id}
		case r.Method == http.MethodGet && len(parts) == 4:
			m.handleGetRuleset(w, zone, parts[3])
		// POST /zones/{zone}/rulesets/{id}/rules
		case r.Method == http.MethodPost && len(parts) == 5 && parts[4] == "rules":
			m.handleCreateRule(w, r, zone, parts[3])
		// PATCH /zones/{zone}/rulesets/{id}/rules/{ruleID}
		case r.Method == http.MethodPatch && len(parts) == 6 && parts[4] == "rules":
			m.handlePatchRule(w, r, zone, parts[3], parts[5])
		// DELETE /zones/{zone}/rulesets/{id}/rules/{ruleID}
		case r.Method == http.MethodDelete && len(parts) == 6 && parts[4] == "rules":
			m.handleDeleteRule(w, zone, parts[3], parts[5])
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

// wire types used only in the mock

type cfMockRulesetInfo struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
}

type cfMockRulesetDetail struct {
	ID    string           `json:"id"`
	Phase string           `json:"phase"`
	Rules []cfMockWireRule `json:"rules"`
}

type cfMockWireRule struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
}

type cfMockRuleReq struct {
	Action      string `json:"action"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
}

type cfMockCreateRulesetReq struct {
	Name  string          `json:"name"`
	Kind  string          `json:"kind"`
	Phase string          `json:"phase"`
	Rules []cfMockRuleReq `json:"rules"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func cfSuccess(result any) map[string]any {
	return map[string]any{"success": true, "errors": []any{}, "result": result}
}

func cfError(code int, msg string) map[string]any {
	return map[string]any{
		"success": false,
		"errors":  []map[string]any{{"code": code, "message": msg}},
	}
}

func (m *cfMock) handleListRulesets(w http.ResponseWriter, zone string) {
	m.mu.Lock()
	z := m.zoneNoLock(zone)
	var result []cfMockRulesetInfo
	if z.rulesetID != "" {
		result = []cfMockRulesetInfo{{ID: z.rulesetID, Phase: "http_request_firewall_custom"}}
	}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(result))
}

func (m *cfMock) handleCreateRuleset(w http.ResponseWriter, r *http.Request, zone string) {
	var req cfMockCreateRulesetReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	z := m.zoneNoLock(zone)
	z.rulesetID = m.genID()
	var wireRules []cfMockWireRule
	for _, rr := range req.Rules {
		id := m.genID()
		z.rules[id] = &cfMockRule{ID: id, Action: rr.Action, Expression: rr.Expression, Description: rr.Description}
		wireRules = append(wireRules, cfMockWireRule{ID: id, Action: rr.Action, Expression: rr.Expression, Description: rr.Description})
	}
	detail := cfMockRulesetDetail{ID: z.rulesetID, Phase: "http_request_firewall_custom", Rules: wireRules}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(detail))
}

func (m *cfMock) handleGetRuleset(w http.ResponseWriter, zone, rulesetID string) {
	m.mu.Lock()
	z := m.zoneNoLock(zone)
	if z.rulesetID != rulesetID {
		m.mu.Unlock()
		writeJSON(w, cfError(1002, "ruleset not found"))
		return
	}
	var wireRules []cfMockWireRule
	for _, r := range z.rules {
		wireRules = append(wireRules, cfMockWireRule{ID: r.ID, Action: r.Action, Expression: r.Expression, Description: r.Description})
	}
	detail := cfMockRulesetDetail{ID: rulesetID, Phase: "http_request_firewall_custom", Rules: wireRules}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(detail))
}

func (m *cfMock) handleCreateRule(w http.ResponseWriter, r *http.Request, zone, rulesetID string) {
	var req cfMockRuleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	z := m.zoneNoLock(zone)
	id := m.genID()
	rule := &cfMockRule{ID: id, Action: req.Action, Expression: req.Expression, Description: req.Description}
	z.rules[id] = rule
	wire := cfMockWireRule{ID: id, Action: rule.Action, Expression: rule.Expression, Description: rule.Description}
	m.mu.Unlock()
	writeJSON(w, cfSuccess(wire))
}

func (m *cfMock) handlePatchRule(w http.ResponseWriter, r *http.Request, zone, rulesetID, ruleID string) {
	var req cfMockRuleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	z := m.zoneNoLock(zone)
	rule, ok := z.rules[ruleID]
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

func (m *cfMock) handleDeleteRule(w http.ResponseWriter, zone, rulesetID, ruleID string) {
	m.mu.Lock()
	z := m.zoneNoLock(zone)
	_, ok := z.rules[ruleID]
	if ok {
		delete(z.rules, ruleID)
	}
	m.mu.Unlock()
	if !ok {
		writeJSON(w, cfError(1002, "rule not found"))
		return
	}
	writeJSON(w, cfSuccess(map[string]string{"id": ruleID}))
}

// ── mock inspection helpers ───────────────────────────────────────────────────

// hasRule reports whether ip/cidr appears as a whole token inside any rule's expression.
func (m *cfMock) hasRule(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, z := range m.zones {
		for _, r := range z.rules {
			if exprContains(r.Expression, ip) {
				return true
			}
		}
	}
	return false
}

// ruleCount returns total WAF rules across all zones.
func (m *cfMock) ruleCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, z := range m.zones {
		n += len(z.rules)
	}
	return n
}

// exprContains checks whether ip appears as a whole token (space- or brace-delimited)
// inside a Cloudflare expression like "(ip.src in {a b c})".
func exprContains(expr, ip string) bool {
	return strings.Contains(expr, " "+ip+" ") ||
		strings.Contains(expr, "{"+ip+" ") ||
		strings.Contains(expr, " "+ip+"}") ||
		strings.Contains(expr, "{"+ip+"}")
}

// newMockCFServer starts an httptest server backed by cfMock.
func newMockCFServer(t *testing.T) (*cfMock, *httptest.Server) {
	t.Helper()
	mock := newCFMock()
	ts := httptest.NewServer(mock.handler())
	t.Cleanup(ts.Close)
	return mock, ts
}

// ── Ban tests ─────────────────────────────────────────────────────────────────

func TestCFBan_CreatesRule(t *testing.T) {
	mock, ts := newMockCFServer(t)
	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1"})

	ip := netip.MustParseAddr("1.2.3.4")
	if err := e.Ban(context.Background(), sdk.Target{IP: ip, TTL: time.Hour}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if !mock.hasRule("1.2.3.4") {
		t.Error("expected 1.2.3.4 in expression after Ban")
	}
}

func TestCFBan_CIDRTarget(t *testing.T) {
	mock, ts := newMockCFServer(t)
	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1"})

	pfx := netip.MustParsePrefix("10.0.0.0/8")
	if err := e.Ban(context.Background(), sdk.Target{Prefix: pfx}); err != nil {
		t.Fatalf("Ban CIDR: %v", err)
	}
	if !mock.hasRule("10.0.0.0/8") {
		t.Error("expected 10.0.0.0/8 in expression after Ban")
	}
}

func TestCFBan_MultiZone_BansEach(t *testing.T) {
	mock, ts := newMockCFServer(t)
	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1", "zone2"})

	ip := netip.MustParseAddr("5.5.5.5")
	if err := e.Ban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	// Each zone gets its own WAF rule → 2 rules total.
	if mock.ruleCount() != 2 {
		t.Errorf("expected 2 rules (one per zone), got %d", mock.ruleCount())
	}
	if !mock.hasRule("5.5.5.5") {
		t.Error("expected 5.5.5.5 in at least one zone's expression")
	}
}

func TestCFBan_AllowlistedIP_Refused(t *testing.T) {
	mock, ts := newMockCFServer(t)
	allowIP := netip.MustParseAddr("10.0.0.1")
	e := enforce.NewCFEnforcerWithAllowlist("tok", ts.URL, []string{"zone1"},
		[]netip.Prefix{netip.PrefixFrom(allowIP, 32)})

	err := e.Ban(context.Background(), sdk.Target{IP: allowIP, TTL: time.Minute})
	if err == nil {
		t.Fatal("expected error banning allowlisted IP, got nil")
	}
	if mock.ruleCount() != 0 {
		t.Error("expected no API calls for allowlisted IP")
	}
}

func TestCFBan_ASNTarget_Rejected(t *testing.T) {
	_, ts := newMockCFServer(t)
	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1"})

	err := e.Ban(context.Background(), sdk.Target{ASN: 1234})
	if err == nil {
		t.Fatal("expected error for ASN target (not supported)")
	}
}

func TestCFBan_RuleDescription(t *testing.T) {
	mock, ts := newMockCFServer(t)
	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1"})

	ip := netip.MustParseAddr("9.9.9.9")
	if err := e.Ban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	z, ok := mock.zones["zone1"]
	if !ok || len(z.rules) == 0 {
		t.Fatal("expected a rule in zone1")
	}
	for _, r := range z.rules {
		if r.Description != "ezyshield-blocklist" {
			t.Errorf("rule description = %q, want %q", r.Description, "ezyshield-blocklist")
		}
	}
}

// ── Unban tests ───────────────────────────────────────────────────────────────

func TestCFUnban_RemovesIPFromExpression(t *testing.T) {
	mock, ts := newMockCFServer(t)
	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1"})

	ip := netip.MustParseAddr("7.7.7.7")
	if err := e.Ban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if mock.ruleCount() != 1 {
		t.Fatal("expected 1 rule after ban")
	}
	if err := e.Unban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	// Rule is deleted when the set becomes empty.
	if mock.ruleCount() != 0 {
		t.Errorf("expected 0 rules after unban of last IP, got %d", mock.ruleCount())
	}
}

func TestCFUnban_PartialRemoval(t *testing.T) {
	mock, ts := newMockCFServer(t)
	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1"})

	for _, s := range []string{"1.1.1.1", "2.2.2.2"} {
		a := netip.MustParseAddr(s)
		if err := e.Ban(context.Background(), sdk.Target{IP: a}); err != nil {
			t.Fatalf("Ban %s: %v", s, err)
		}
	}
	// Unban only 2.2.2.2; 1.1.1.1 should remain in the expression.
	if err := e.Unban(context.Background(), sdk.Target{IP: netip.MustParseAddr("2.2.2.2")}); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if mock.hasRule("2.2.2.2") {
		t.Error("2.2.2.2 should have been removed from expression")
	}
	if !mock.hasRule("1.1.1.1") {
		t.Error("1.1.1.1 should still be in expression")
	}
	if mock.ruleCount() != 1 {
		t.Errorf("expected 1 rule (updated expression), got %d", mock.ruleCount())
	}
}

func TestCFUnban_SkipsNonEzyshieldRules(t *testing.T) {
	mock, ts := newMockCFServer(t)
	// Manually inject a rule with a non-ezyshield description.
	mock.mu.Lock()
	z := mock.zoneNoLock("zone1")
	z.rulesetID = "rs-manual"
	z.rules["rule-manual"] = &cfMockRule{
		ID: "rule-manual", Action: "block",
		Expression:  "(ip.src in {8.8.8.8})",
		Description: "manually created",
	}
	mock.mu.Unlock()

	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1"})
	// Unban 8.8.8.8 which ezyshield never banned — must be a no-op.
	if err := e.Unban(context.Background(), sdk.Target{IP: netip.MustParseAddr("8.8.8.8")}); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	// The manual rule must remain untouched.
	if mock.ruleCount() != 1 {
		t.Errorf("expected 1 rule (non-ezyshield), got %d", mock.ruleCount())
	}
}

func TestCFUnban_NoRule_NoError(t *testing.T) {
	_, ts := newMockCFServer(t)
	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1"})

	// Unban an IP never banned — must be a no-op, not an error.
	if err := e.Unban(context.Background(), sdk.Target{IP: netip.MustParseAddr("3.3.3.3")}); err != nil {
		t.Fatalf("Unban on absent IP returned error: %v", err)
	}
}

// ── Sync tests ────────────────────────────────────────────────────────────────

func TestCFSync_AddsMissingRemovesStale(t *testing.T) {
	mock, ts := newMockCFServer(t)
	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1"})

	// Pre-ban 1.1.1.1 (keep) and 2.2.2.2 (stale → remove).
	for _, s := range []string{"1.1.1.1", "2.2.2.2"} {
		a := netip.MustParseAddr(s)
		if err := e.Ban(context.Background(), sdk.Target{IP: a}); err != nil {
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

	if mock.hasRule("2.2.2.2") {
		t.Error("stale 2.2.2.2 should have been removed")
	}
	if !mock.hasRule("1.1.1.1") {
		t.Error("1.1.1.1 should still be present")
	}
	if !mock.hasRule("3.3.3.3") {
		t.Error("3.3.3.3 should have been added")
	}
}

func TestCFSync_EmptyWant_RemovesAll(t *testing.T) {
	mock, ts := newMockCFServer(t)
	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1"})

	for _, s := range []string{"1.1.1.1", "2.2.2.2"} {
		a := netip.MustParseAddr(s)
		if err := e.Ban(context.Background(), sdk.Target{IP: a}); err != nil {
			t.Fatalf("pre-ban: %v", err)
		}
	}
	if err := e.Sync(context.Background(), nil); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if mock.ruleCount() != 0 {
		t.Errorf("expected 0 rules after sync with empty want, got %d", mock.ruleCount())
	}
}

func TestCFSync_SkipsAllowlisted(t *testing.T) {
	mock, ts := newMockCFServer(t)
	allow := netip.MustParsePrefix("10.0.0.0/8")
	e := enforce.NewCFEnforcerWithAllowlist("tok", ts.URL, []string{"zone1"},
		[]netip.Prefix{allow})

	want := []sdk.Target{
		{IP: netip.MustParseAddr("10.1.2.3")}, // allowlisted — skip
		{IP: netip.MustParseAddr("5.5.5.5")},  // not allowlisted — ban
	}
	if err := e.Sync(context.Background(), want); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if mock.hasRule("10.1.2.3") {
		t.Error("allowlisted 10.1.2.3 must not appear in expression")
	}
	if !mock.hasRule("5.5.5.5") {
		t.Error("5.5.5.5 should be in expression")
	}
}

func TestCFSync_PreservesNonEzyshieldRules(t *testing.T) {
	mock, ts := newMockCFServer(t)
	// Inject a rule with a description unrelated to ezyshield.
	mock.mu.Lock()
	z := mock.zoneNoLock("zone1")
	z.rulesetID = "rs-ext"
	z.rules["rule-ext"] = &cfMockRule{
		ID: "rule-ext", Action: "block",
		Expression:  "(ip.src in {99.99.99.99})",
		Description: "manually created",
	}
	mock.mu.Unlock()

	e := enforce.NewCFEnforcerForTest("tok", ts.URL, []string{"zone1"})
	// Sync with empty want — must not delete the non-ezyshield rule.
	if err := e.Sync(context.Background(), nil); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !mock.hasRule("99.99.99.99") {
		t.Error("non-ezyshield rule should not be removed by Sync")
	}
}

// ── Expression split (>4 KB) tests ────────────────────────────────────────────

func TestCFBan_ExpressionSplit(t *testing.T) {
	mock, ts := newMockCFServer(t)
	// Use a very small exprMax so that a handful of IPs forces a second rule.
	// "(ip.src in {" = 12, "})" = 2 → overhead 14 bytes.
	// "1.2.3.1" = 7 bytes. At limit=40: 14 + 7 = 21 fits; +8 (space+ip) = 29; +8 = 37; +8 = 45 > 40.
	// So rule 1 fits 3 IPs, rule 2 gets the rest.
	e := enforce.NewCFEnforcerWithExprMax("tok", ts.URL, []string{"zone1"}, 40)

	for i := 1; i <= 8; i++ {
		ip := netip.MustParseAddr(fmt.Sprintf("1.2.3.%d", i))
		if err := e.Ban(context.Background(), sdk.Target{IP: ip}); err != nil {
			t.Fatalf("Ban 1.2.3.%d: %v", i, err)
		}
	}

	if mock.ruleCount() < 2 {
		t.Errorf("expected ≥2 rules for split expression, got %d", mock.ruleCount())
	}
	for i := 1; i <= 8; i++ {
		ip := fmt.Sprintf("1.2.3.%d", i)
		if !mock.hasRule(ip) {
			t.Errorf("expected %s to be in an expression", ip)
		}
	}
}

func TestCFSync_ExpressionSplitThenShrink(t *testing.T) {
	mock, ts := newMockCFServer(t)
	e := enforce.NewCFEnforcerWithExprMax("tok", ts.URL, []string{"zone1"}, 40)

	// Sync 8 IPs → forces 2 rules.
	var big []sdk.Target
	for i := 1; i <= 8; i++ {
		big = append(big, sdk.Target{IP: netip.MustParseAddr(fmt.Sprintf("1.2.3.%d", i))})
	}
	if err := e.Sync(context.Background(), big); err != nil {
		t.Fatalf("Sync big: %v", err)
	}
	if mock.ruleCount() < 2 {
		t.Fatalf("expected ≥2 rules after big sync, got %d", mock.ruleCount())
	}

	// Sync down to 2 IPs → should collapse to 1 rule.
	small := []sdk.Target{
		{IP: netip.MustParseAddr("1.2.3.1")},
		{IP: netip.MustParseAddr("1.2.3.2")},
	}
	if err := e.Sync(context.Background(), small); err != nil {
		t.Fatalf("Sync small: %v", err)
	}
	if mock.ruleCount() != 1 {
		t.Errorf("expected 1 rule after small sync, got %d", mock.ruleCount())
	}
	if !mock.hasRule("1.2.3.1") || !mock.hasRule("1.2.3.2") {
		t.Error("remaining IPs should still be present")
	}
}

// ── Debounce test ─────────────────────────────────────────────────────────────

func TestCFBan_Debounce_BatchesPushes(t *testing.T) {
	mock, ts := newMockCFServer(t)
	// Short debounce so the test doesn't take long.
	e := enforce.NewCFEnforcerWithDebounce("tok", ts.URL, []string{"zone1"}, 40*time.Millisecond)

	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	for _, s := range ips {
		a := netip.MustParseAddr(s)
		// Ban returns immediately (no synchronous push) when debounce > 0.
		if err := e.Ban(context.Background(), sdk.Target{IP: a}); err != nil {
			t.Fatalf("Ban %s: %v", s, err)
		}
	}
	// Before debounce fires, nothing should be in CF yet.
	if mock.ruleCount() != 0 {
		t.Errorf("expected 0 rules before debounce fires, got %d", mock.ruleCount())
	}

	// Wait for debounce to fire and settle.
	time.Sleep(120 * time.Millisecond)

	for _, s := range ips {
		if !mock.hasRule(s) {
			t.Errorf("expected %s in expression after debounce", s)
		}
	}
	// Debounce should have coalesced all 4 bans into a single push (2 API calls:
	// 1 GET list rulesets + 1 POST create ruleset+rule). Allow a small margin.
	if got := mock.reqCount.Load(); got > 4 {
		t.Errorf("too many API requests (%d); debounce should have batched", got)
	}
}

func TestCFBan_Debounce_ContextCancelSkipsFlush(t *testing.T) {
	mock, ts := newMockCFServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	e := enforce.NewCFEnforcerWithDebounceAndCtx(ctx, "tok", ts.URL, []string{"zone1"}, 50*time.Millisecond)

	if err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("9.9.9.9")}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	// Cancel the service context before the debounce timer fires.
	cancel()
	time.Sleep(120 * time.Millisecond)

	if mock.ruleCount() != 0 {
		t.Errorf("expected 0 CF rules after service context cancel, got %d", mock.ruleCount())
	}
}

// ── Name test ─────────────────────────────────────────────────────────────────

func TestCFName(t *testing.T) {
	e := enforce.NewCFEnforcerForTest("tok", "http://localhost", []string{"z1"})
	if got := e.Name(); got != "cloudflare" {
		t.Errorf("Name() = %q, want 'cloudflare'", got)
	}
}

// ── Secret-leak gate (SECURITY-REVIEW §4) ─────────────────────────────────────

func TestCFBan_TokenNotInError(t *testing.T) {
	const secret = "SUPER-SECRET-CF-TOKEN-xyz999"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"errors":  []map[string]any{{"code": 403, "message": "Forbidden"}},
		})
	}))
	defer ts.Close()

	e := enforce.NewCFEnforcerForTest(secret, ts.URL, []string{"zone1"})
	err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("1.2.3.4")})
	if err == nil {
		t.Fatal("expected error from API failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("API token leaked into error message: %q", err.Error())
	}
}

// ── MultiEnforcer tests ───────────────────────────────────────────────────────

func TestMultiEnforcer_Name(t *testing.T) {
	m := enforce.NewMulti(
		enforce.NewCFEnforcerForTest("t", "http://localhost", []string{"z"}),
		enforce.NewCFEnforcerForTest("t", "http://localhost", []string{"z"}),
	)
	if got := m.Name(); got != "cloudflare+cloudflare" {
		t.Errorf("Name() = %q", got)
	}
}

func TestMultiEnforcer_BanBothEnforcers(t *testing.T) {
	mock1, ts1 := newMockCFServer(t)
	mock2, ts2 := newMockCFServer(t)
	e1 := enforce.NewCFEnforcerForTest("t", ts1.URL, []string{"z"})
	e2 := enforce.NewCFEnforcerForTest("t", ts2.URL, []string{"z"})
	m := enforce.NewMulti(e1, e2)

	ip := netip.MustParseAddr("1.2.3.4")
	if err := m.Ban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if !mock1.hasRule("1.2.3.4") {
		t.Error("enforcer 1 should have 1.2.3.4 in its expression")
	}
	if !mock2.hasRule("1.2.3.4") {
		t.Error("enforcer 2 should have 1.2.3.4 in its expression")
	}
}

func TestMultiEnforcer_ContinuesOnPartialFailure(t *testing.T) {
	mock2, ts2 := newMockCFServer(t)
	e1 := enforce.NewCFEnforcerForTest("t", "http://127.0.0.1:1", []string{"z"})
	e2 := enforce.NewCFEnforcerForTest("t", ts2.URL, []string{"z"})
	m := enforce.NewMulti(e1, e2)

	ip := netip.MustParseAddr("2.2.2.2")
	err := m.Ban(context.Background(), sdk.Target{IP: ip})
	if err == nil {
		t.Error("expected combined error from partial failure")
	}
	if !mock2.hasRule("2.2.2.2") {
		t.Error("e2 should have 2.2.2.2 even though e1 failed")
	}
}
