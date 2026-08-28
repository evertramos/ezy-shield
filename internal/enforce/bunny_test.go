// SPDX-License-Identifier: AGPL-3.0-only

package enforce_test

// Tests for the bunny.net edge enforcer (issue #197): mock HTTP server
// standing in for api.bunny.net (no real network), covering ban, unban,
// sync reconcile, 429 retry, auth failure, malformed responses, per-zone
// failure isolation, the capacity guard, and the secret-leak gate.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const testBunnyKey = "test-bunny-access-key"

// bunnyMock is a minimal stand-in for the bunny.net pull-zone API.
type bunnyMock struct {
	mu    sync.Mutex
	key   string
	zones map[int64][]string // zone id → blocked IPs (ordered)
	calls []string           // "verb:zone:ip" / "get:zone"
	// Test knobs
	throttleNext  int   // next N mutations answer 429
	retryAfterSec int   // Retry-After header on throttles (0 = none)
	failZone      int64 // this zone answers 500 on every request
	garbageGet    bool  // GET answers non-JSON garbage
}

func newBunnyMock(zones ...int64) *bunnyMock {
	m := &bunnyMock{key: testBunnyKey, zones: map[int64][]string{}}
	for _, z := range zones {
		m.zones[z] = nil
	}
	return m
}

func (m *bunnyMock) server(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(ts.Close)
	return ts
}

func (m *bunnyMock) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("AccessKey") != m.key {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"ErrorKey":"unauthorized","Message":"Authorization failed"}`) //nolint:errcheck
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "pullzone" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	zone, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failZone != 0 && zone == m.failZone {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"Message":"internal error"}`) //nolint:errcheck
		return
	}
	ips, ok := m.zones[zone]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"ErrorKey":"pullzone.not_found","Message":"Pull Zone not found"}`) //nolint:errcheck
		return
	}

	if len(parts) == 2 && r.Method == http.MethodGet {
		m.calls = append(m.calls, "get:"+parts[1])
		if m.garbageGet {
			fmt.Fprint(w, "<html>this is not json</html>") //nolint:errcheck
			return
		}
		// Extra fields mirror the real (huge) pull-zone object: the decoder
		// must tolerate them.
		resp := map[string]any{"Id": zone, "Name": "zone", "BlockedIps": ips, "EnableLogging": true}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	if len(parts) == 3 && r.Method == http.MethodPost {
		verb := parts[2]
		if verb != "addBlockedIp" && verb != "removeBlockedIp" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if m.throttleNext > 0 {
			m.throttleNext--
			if m.retryAfterSec > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(m.retryAfterSec))
			}
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		var body struct {
			BlockedIp string `json:"BlockedIp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.BlockedIp == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"ErrorKey":"blockedip.invalid","Message":"The IP is invalid"}`) //nolint:errcheck
			return
		}
		m.calls = append(m.calls, verb+":"+parts[1]+":"+body.BlockedIp)
		switch verb {
		case "addBlockedIp":
			for _, ip := range ips {
				if ip == body.BlockedIp {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
			m.zones[zone] = append(ips, body.BlockedIp)
		case "removeBlockedIp":
			out := ips[:0]
			for _, ip := range ips {
				if ip != body.BlockedIp {
					out = append(out, ip)
				}
			}
			m.zones[zone] = out
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (m *bunnyMock) blocked(zone int64) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.zones[zone]...)
}

func (m *bunnyMock) mutationCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, c := range m.calls {
		if !strings.HasPrefix(c, "get:") {
			out = append(out, c)
		}
	}
	return out
}

func bunnyTarget(t *testing.T, ip string) sdk.Target {
	t.Helper()
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		t.Fatalf("parse %s: %v", ip, err)
	}
	return sdk.Target{IP: addr}
}

// ── Ban / Unban ──────────────────────────────────────────────────────────────

func TestBunnyBan_AppliesToAllZones(t *testing.T) {
	m := newBunnyMock(101, 202)
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerForTest(testBunnyKey, ts.URL, []int64{101, 202})
	ctx := context.Background()

	if err := e.Ban(ctx, bunnyTarget(t, "192.0.2.10")); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	for _, zone := range []int64{101, 202} {
		got := m.blocked(zone)
		if len(got) != 1 || got[0] != "192.0.2.10" {
			t.Errorf("zone %d blocked = %v, want [192.0.2.10]", zone, got)
		}
	}
	// Second ban of the same IP is a no-op (list is a set; skip the call).
	before := len(m.mutationCalls())
	if err := e.Ban(ctx, bunnyTarget(t, "192.0.2.10")); err != nil {
		t.Fatalf("repeat Ban: %v", err)
	}
	if after := len(m.mutationCalls()); after != before {
		t.Errorf("repeat Ban issued %d extra API calls", after-before)
	}
}

func TestBunnyUnban_RemovesFromAllZones(t *testing.T) {
	m := newBunnyMock(101, 202)
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerForTest(testBunnyKey, ts.URL, []int64{101, 202})
	ctx := context.Background()

	if err := e.Ban(ctx, bunnyTarget(t, "192.0.2.20")); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if err := e.Unban(ctx, bunnyTarget(t, "192.0.2.20")); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	for _, zone := range []int64{101, 202} {
		if got := m.blocked(zone); len(got) != 0 {
			t.Errorf("zone %d blocked = %v, want empty", zone, got)
		}
	}
}

func TestBunnyBan_AllowlistedRefusedWithoutAPICall(t *testing.T) {
	m := newBunnyMock(101)
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerWithAllowlist(testBunnyKey, ts.URL, []int64{101},
		[]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})

	err := e.Ban(context.Background(), bunnyTarget(t, "192.0.2.5"))
	if err == nil || !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("want allowlist refusal, got %v", err)
	}
	if calls := m.mutationCalls(); len(calls) != 0 {
		t.Errorf("allowlisted ban reached the API: %v", calls)
	}
}

// ── Sync reconcile ───────────────────────────────────────────────────────────

func TestBunnySync_Reconciles(t *testing.T) {
	m := newBunnyMock(101)
	m.zones[101] = []string{"198.51.100.1", "198.51.100.2", "not-an-ip"}
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerForTest(testBunnyKey, ts.URL, []int64{101})
	ctx := context.Background()

	want := []sdk.Target{
		bunnyTarget(t, "198.51.100.2"), // already present → untouched
		bunnyTarget(t, "203.0.113.9"),  // missing → added
	}
	if err := e.Sync(ctx, want); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	got := m.blocked(101)
	gotSet := map[string]bool{}
	for _, ip := range got {
		gotSet[ip] = true
	}
	if !gotSet["198.51.100.2"] || !gotSet["203.0.113.9"] || gotSet["198.51.100.1"] {
		t.Fatalf("after Sync blocked = %v, want kept 198.51.100.2, added 203.0.113.9, removed 198.51.100.1", got)
	}

	// Idempotent: a second identical Sync issues no mutations.
	before := len(m.mutationCalls())
	if err := e.Sync(ctx, want); err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	if after := len(m.mutationCalls()); after != before {
		t.Errorf("idempotent Sync issued %d extra mutations", after-before)
	}
}

func TestBunnySync_PartialZoneFailureContinues(t *testing.T) {
	m := newBunnyMock(101, 202)
	m.failZone = 101
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerForTest(testBunnyKey, ts.URL, []int64{101, 202})

	err := e.Sync(context.Background(), []sdk.Target{bunnyTarget(t, "192.0.2.30")})
	if err == nil || !strings.Contains(err.Error(), "zone 101") {
		t.Fatalf("want joined error naming zone 101, got %v", err)
	}
	if strings.Contains(err.Error(), "zone 202") {
		t.Errorf("healthy zone 202 appears in the error: %v", err)
	}
	if got := m.blocked(202); len(got) != 1 || got[0] != "192.0.2.30" {
		t.Errorf("zone 202 not reconciled despite zone 101 failure: %v", got)
	}
}

func TestBunnySync_AllowlistedSkipped(t *testing.T) {
	m := newBunnyMock(101)
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerWithAllowlist(testBunnyKey, ts.URL, []int64{101},
		[]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})

	err := e.Sync(context.Background(), []sdk.Target{
		bunnyTarget(t, "192.0.2.5"),   // allowlisted → skipped silently
		bunnyTarget(t, "203.0.113.7"), // applied
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	got := m.blocked(101)
	if len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("blocked = %v, want only 203.0.113.7", got)
	}
}

// ── Retry / errors ───────────────────────────────────────────────────────────

func TestBunnyBan_RetriesOn429(t *testing.T) {
	m := newBunnyMock(101)
	m.throttleNext = 2
	m.retryAfterSec = 0
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerWithRetryDelays(testBunnyKey, ts.URL, []int64{101},
		[]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond})

	if err := e.Ban(context.Background(), bunnyTarget(t, "192.0.2.40")); err != nil {
		t.Fatalf("Ban should succeed after retries: %v", err)
	}
	if got := m.blocked(101); len(got) != 1 {
		t.Fatalf("blocked = %v, want the banned IP after retry", got)
	}
}

func TestBunnyBan_RetryExhaustionFails(t *testing.T) {
	m := newBunnyMock(101)
	m.throttleNext = 100
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerWithRetryDelays(testBunnyKey, ts.URL, []int64{101},
		[]time.Duration{time.Millisecond})

	err := e.Ban(context.Background(), bunnyTarget(t, "192.0.2.41"))
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("want 429 exhaustion error, got %v", err)
	}
}

func TestBunnyAuthFailure(t *testing.T) {
	m := newBunnyMock(101)
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerForTest("wrong-key", ts.URL, []int64{101})

	err := e.Ban(context.Background(), bunnyTarget(t, "192.0.2.50"))
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want 401 error, got %v", err)
	}
	if strings.Contains(err.Error(), "wrong-key") {
		t.Errorf("access key leaked into error: %q", err.Error())
	}
}

func TestBunnySync_MalformedResponse(t *testing.T) {
	m := newBunnyMock(101)
	m.garbageGet = true
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerForTest(testBunnyKey, ts.URL, []int64{101})

	err := e.Sync(context.Background(), []sdk.Target{bunnyTarget(t, "192.0.2.60")})
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("want malformed-response error, got %v", err)
	}
}

// ── Capacity guard ───────────────────────────────────────────────────────────

func TestBunnyCapacity_SyncKeepsNewest(t *testing.T) {
	m := newBunnyMock(101)
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerWithZoneCap(testBunnyKey, ts.URL, []int64{101}, 2)

	// Sync input arrives oldest-first; the cap must keep the tail (newest).
	err := e.Sync(context.Background(), []sdk.Target{
		bunnyTarget(t, "192.0.2.1"),
		bunnyTarget(t, "192.0.2.2"),
		bunnyTarget(t, "192.0.2.3"),
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	got := m.blocked(101)
	if len(got) != 2 {
		t.Fatalf("blocked = %v, want exactly 2 (cap)", got)
	}
	gotSet := map[string]bool{got[0]: true, got[1]: true}
	if !gotSet["192.0.2.2"] || !gotSet["192.0.2.3"] {
		t.Errorf("cap kept the wrong entries: %v (want the 2 newest)", got)
	}
}

func TestBunnyCapacity_BanEvictsOldest(t *testing.T) {
	m := newBunnyMock(101)
	ts := m.server(t)
	e := enforce.NewBunnyEnforcerWithZoneCap(testBunnyKey, ts.URL, []int64{101}, 2)
	ctx := context.Background()

	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if err := e.Ban(ctx, bunnyTarget(t, ip)); err != nil {
			t.Fatalf("Ban %s: %v", ip, err)
		}
	}
	got := m.blocked(101)
	gotSet := map[string]bool{}
	for _, ip := range got {
		gotSet[ip] = true
	}
	if len(got) != 2 || gotSet["192.0.2.1"] || !gotSet["192.0.2.2"] || !gotSet["192.0.2.3"] {
		t.Fatalf("blocked = %v, want oldest 192.0.2.1 evicted, 2 newest kept", got)
	}
}

// ── Construction ─────────────────────────────────────────────────────────────

func TestNewBunnyEnforcer_ConstructionGuards(t *testing.T) {
	t.Setenv("BUNNY_TEST_ACCESS_KEY", "resolved-key")

	// Missing env var fails construction, not enforcement.
	if _, err := enforce.NewBunnyEnforcer(&enforce.BunnyConfig{
		AccessKey:   config.SecretRef("env:BUNNY_TEST_MISSING_VAR"),
		PullZoneIDs: []int64{1},
	}, nil); err == nil {
		t.Error("want error for unresolvable access key")
	}

	// No pull zones is a construction error.
	if _, err := enforce.NewBunnyEnforcer(&enforce.BunnyConfig{
		AccessKey: config.SecretRef("env:BUNNY_TEST_ACCESS_KEY"),
	}, nil); err == nil || !strings.Contains(err.Error(), "pull zone") {
		t.Errorf("want pull-zone requirement error, got %v", err)
	}

	// Valid config constructs and names itself.
	e, err := enforce.NewBunnyEnforcer(&enforce.BunnyConfig{
		AccessKey:   config.SecretRef("env:BUNNY_TEST_ACCESS_KEY"),
		PullZoneIDs: []int64{1, 2},
		Name:        "edge-b",
	}, nil)
	if err != nil {
		t.Fatalf("NewBunnyEnforcer: %v", err)
	}
	if e.Name() != "bunny[edge-b]" {
		t.Errorf("Name() = %q, want bunny[edge-b]", e.Name())
	}
}

// ── Name / secret-leak gate (SECURITY-REVIEW §4) ─────────────────────────────

func TestBunnyName(t *testing.T) {
	e := enforce.NewBunnyEnforcerForTest(testBunnyKey, "http://unused", []int64{1})
	if e.Name() != "bunny" {
		t.Errorf("Name() = %q, want bunny", e.Name())
	}
	named := enforce.NewBunnyEnforcerWithName("edge-a", testBunnyKey, "http://unused", []int64{1})
	if named.Name() != "bunny[edge-a]" {
		t.Errorf("Name() = %q, want bunny[edge-a]", named.Name())
	}
}

func TestBunnySecretNeverLeaks(t *testing.T) {
	const secret = "SUPER-SECRET-BUNNY-KEY-zzz999"
	// Server always fails with a body echoing nothing sensitive; every error
	// path (500, 401, transport) must keep the key out of error text.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"Message":"boom"}`) //nolint:errcheck
	}))
	t.Cleanup(ts.Close)
	e := enforce.NewBunnyEnforcerForTest(secret, ts.URL, []int64{101})
	ctx := context.Background()

	for name, err := range map[string]error{
		"ban":   e.Ban(ctx, bunnyTarget(t, "192.0.2.70")),
		"unban": e.Unban(ctx, bunnyTarget(t, "192.0.2.70")),
		"sync":  e.Sync(ctx, []sdk.Target{bunnyTarget(t, "192.0.2.70")}),
	} {
		if err == nil {
			t.Fatalf("%s: want error from failing server", name)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: access key leaked into error: %q", name, err.Error())
		}
	}
}
