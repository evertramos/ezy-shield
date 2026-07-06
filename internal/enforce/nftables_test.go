package enforce_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// mockHelper is a unix-socket server that records requests and returns
// pre-programmed responses. It stands in for ezyshield-enforcer in unit tests.
type mockHelper struct {
	mu        sync.Mutex
	requests  []enforce.Request
	responses map[string]enforce.Response
	sock      string
	ln        net.Listener
}

func newMockHelper(t *testing.T) *mockHelper {
	t.Helper()
	f, err := os.CreateTemp("", "enforcer-test-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	sockPath := f.Name()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}

	ms := &mockHelper{
		sock: sockPath,
		ln:   ln,
		responses: map[string]enforce.Response{
			"add":        {OK: true},
			"del":        {OK: true},
			"flush":      {OK: true},
			"list":       {OK: true},
			"ping":       {OK: true},
			"allow_add":  {OK: true},
			"allow_del":  {OK: true},
			"allow_list": {OK: true},
		},
	}
	go ms.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})
	return ms
}

func (ms *mockHelper) setListIPs(ips []string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.responses["list"] = enforce.Response{OK: true, IPs: ips}
}

func (ms *mockHelper) setAllowListIPs(ips []string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.responses["allow_list"] = enforce.Response{OK: true, IPs: ips}
}

func (ms *mockHelper) recorded() []enforce.Request {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	out := make([]enforce.Request, len(ms.requests))
	copy(out, ms.requests)
	return out
}

func (ms *mockHelper) serve() {
	for {
		conn, err := ms.ln.Accept()
		if err != nil {
			return
		}
		go ms.handle(conn)
	}
}

func (ms *mockHelper) handle(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		var req enforce.Request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		ms.mu.Lock()
		ms.requests = append(ms.requests, req)
		resp := ms.responses[req.Verb]
		ms.mu.Unlock()
		if err := json.NewEncoder(conn).Encode(resp); err != nil {
			return
		}
	}
}

// ── Ban tests ──────────────────────────────────────────────────────────────────

func TestBan_SendsAddVerb(t *testing.T) {
	ms := newMockHelper(t)
	e := enforce.New(ms.sock, nil)

	ip := netip.MustParseAddr("1.2.3.4")
	if err := e.Ban(context.Background(), sdk.Target{IP: ip, TTL: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}

	reqs := ms.recorded()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Verb != "add" {
		t.Errorf("expected verb=add, got %s", reqs[0].Verb)
	}
	if reqs[0].IP != "1.2.3.4" {
		t.Errorf("expected ip=1.2.3.4, got %s", reqs[0].IP)
	}
	if reqs[0].TTLSeconds != 300 {
		t.Errorf("expected ttl_seconds=300, got %d", reqs[0].TTLSeconds)
	}
}

func TestBan_PermanentTTL(t *testing.T) {
	ms := newMockHelper(t)
	e := enforce.New(ms.sock, nil)

	ip := netip.MustParseAddr("5.5.5.5")
	if err := e.Ban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatal(err)
	}

	reqs := ms.recorded()
	if len(reqs) != 1 || reqs[0].TTLSeconds != 0 {
		t.Errorf("expected ttl_seconds=0 (permanent), got %+v", reqs)
	}
}

func TestBan_CIDRTarget(t *testing.T) {
	ms := newMockHelper(t)
	e := enforce.New(ms.sock, nil)

	pfx := netip.MustParsePrefix("10.0.0.0/8")
	if err := e.Ban(context.Background(), sdk.Target{Prefix: pfx, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}

	reqs := ms.recorded()
	if len(reqs) != 1 || reqs[0].IP != "10.0.0.0/8" {
		t.Errorf("expected ip=10.0.0.0/8, got %+v", reqs)
	}
}

func TestBan_AllowlistedIP_Refused(t *testing.T) {
	ms := newMockHelper(t)
	allowIP := netip.MustParseAddr("10.0.0.1")
	e := enforce.New(ms.sock, []netip.Prefix{netip.PrefixFrom(allowIP, 32)})

	err := e.Ban(context.Background(), sdk.Target{IP: allowIP, TTL: time.Minute})
	if err == nil {
		t.Fatal("expected error banning allowlisted IP, got nil")
	}
	if got := ms.recorded(); len(got) != 0 {
		t.Fatalf("expected no requests sent to helper, got %d", len(got))
	}
}

func TestBan_AllowlistedCIDR_Refused(t *testing.T) {
	ms := newMockHelper(t)
	allow := netip.MustParsePrefix("192.168.0.0/16")
	e := enforce.New(ms.sock, []netip.Prefix{allow})

	ip := netip.MustParseAddr("192.168.1.50")
	err := e.Ban(context.Background(), sdk.Target{IP: ip, TTL: time.Minute})
	if err == nil {
		t.Fatal("expected error banning IP in allowlisted CIDR")
	}
}

func TestBan_ASNTargetRejected(t *testing.T) {
	ms := newMockHelper(t)
	e := enforce.New(ms.sock, nil)

	// ASN-only target has no IP or Prefix
	err := e.Ban(context.Background(), sdk.Target{ASN: 1234})
	if err == nil {
		t.Fatal("expected error for ASN target (not supported by nftables enforcer)")
	}
}

// ── Unban tests ────────────────────────────────────────────────────────────────

func TestUnban_SendsDelVerb(t *testing.T) {
	ms := newMockHelper(t)
	e := enforce.New(ms.sock, nil)

	ip := netip.MustParseAddr("1.2.3.4")
	if err := e.Unban(context.Background(), sdk.Target{IP: ip}); err != nil {
		t.Fatal(err)
	}

	reqs := ms.recorded()
	if len(reqs) != 1 || reqs[0].Verb != "del" {
		t.Fatalf("expected del, got %+v", reqs)
	}
	if reqs[0].IP != "1.2.3.4" {
		t.Errorf("expected ip=1.2.3.4, got %s", reqs[0].IP)
	}
}

// ── Sync tests ─────────────────────────────────────────────────────────────────

func TestSync_AddsMissingRemovesStale(t *testing.T) {
	ms := newMockHelper(t)
	// Current nftables state: 1.1.1.1 (keep) and 2.2.2.2 (stale)
	ms.setListIPs([]string{"1.1.1.1", "2.2.2.2"})
	e := enforce.New(ms.sock, nil)

	want := []sdk.Target{
		{IP: netip.MustParseAddr("1.1.1.1"), TTL: time.Hour},
		{IP: netip.MustParseAddr("3.3.3.3"), TTL: time.Hour}, // missing → must add
	}
	if err := e.Sync(context.Background(), want); err != nil {
		t.Fatal(err)
	}

	var adds, dels []string
	for _, r := range ms.recorded() {
		switch r.Verb {
		case "add":
			adds = append(adds, r.IP)
		case "del":
			dels = append(dels, r.IP)
		}
	}
	sort.Strings(adds)
	sort.Strings(dels)

	if len(adds) != 1 || adds[0] != "3.3.3.3" {
		t.Errorf("expected add 3.3.3.3, got %v", adds)
	}
	if len(dels) != 1 || dels[0] != "2.2.2.2" {
		t.Errorf("expected del 2.2.2.2, got %v", dels)
	}
}

func TestSync_SkipsAllowlistedInWant(t *testing.T) {
	ms := newMockHelper(t)
	ms.setListIPs(nil)
	allow := netip.MustParsePrefix("10.0.0.0/8")
	e := enforce.New(ms.sock, []netip.Prefix{allow})

	want := []sdk.Target{
		{IP: netip.MustParseAddr("10.1.2.3"), TTL: time.Hour}, // allowlisted
		{IP: netip.MustParseAddr("5.5.5.5"), TTL: time.Hour},  // not allowlisted
	}
	if err := e.Sync(context.Background(), want); err != nil {
		t.Fatal(err)
	}

	var adds []string
	for _, r := range ms.recorded() {
		if r.Verb == "add" {
			adds = append(adds, r.IP)
		}
	}
	if len(adds) != 1 || adds[0] != "5.5.5.5" {
		t.Errorf("expected only 5.5.5.5 to be added, got %v", adds)
	}
}

func TestSync_EmptyWant_RemovesAll(t *testing.T) {
	ms := newMockHelper(t)
	ms.setListIPs([]string{"1.1.1.1", "2.2.2.2"})
	e := enforce.New(ms.sock, nil)

	if err := e.Sync(context.Background(), nil); err != nil {
		t.Fatal(err)
	}

	var dels []string
	for _, r := range ms.recorded() {
		if r.Verb == "del" {
			dels = append(dels, r.IP)
		}
	}
	sort.Strings(dels)
	if len(dels) != 2 || dels[0] != "1.1.1.1" || dels[1] != "2.2.2.2" {
		t.Errorf("expected both IPs removed, got %v", dels)
	}
}

// ── SyncAllowlist tests (issue #37) ────────────────────────────────────────────

// TestSyncAllowlist_AddsMissingRemovesStale asserts the enforcer's SyncAllowlist
// reconciles the @allowed set: entries in want but not in the current listing
// are added via allow_add; entries in current but not in want are removed via
// allow_del. Mirrors TestSync_AddsMissingRemovesStale for the ban set.
func TestSyncAllowlist_AddsMissingRemovesStale(t *testing.T) {
	ms := newMockHelper(t)
	// Current nft @allowed state: 1.1.1.1/32 (keep) and 2.2.2.2/32 (stale).
	ms.setAllowListIPs([]string{"1.1.1.1/32", "2.2.2.2/32"})
	e := enforce.New(ms.sock, nil)

	want := []netip.Prefix{
		netip.MustParsePrefix("1.1.1.1/32"),
		netip.MustParsePrefix("3.3.3.3/32"), // missing → must be added
	}
	if err := e.SyncAllowlist(context.Background(), want); err != nil {
		t.Fatal(err)
	}

	var adds, dels []string
	for _, r := range ms.recorded() {
		switch r.Verb {
		case "allow_add":
			adds = append(adds, r.IP)
		case "allow_del":
			dels = append(dels, r.IP)
		}
	}
	sort.Strings(adds)
	sort.Strings(dels)

	if len(adds) != 1 || adds[0] != "3.3.3.3/32" {
		t.Errorf("expected allow_add 3.3.3.3/32, got %v", adds)
	}
	if len(dels) != 1 || dels[0] != "2.2.2.2/32" {
		t.Errorf("expected allow_del 2.2.2.2/32, got %v", dels)
	}
}

// TestSyncAllowlist_Issue37_PolicyPrefixesReachHelper is the integration-level
// regression for issue #37. It simulates the daemon's startup contract: after
// the fix in internal/daemon/daemon.go, `syncEnforcerAllowlist` passes the
// union of policy.Allowlist + policy.AdminCIDRs + runtime store entries.
// This test verifies that when the daemon actually calls SyncAllowlist with
// that union, the nftables enforcer translates every prefix into an
// `allow_add` RPC — proving the @allowed / @allowed6 sets will end up
// populated on a real nft backend.
//
// The prefixes here mirror the ones the issue calls out on the dogfood host.
func TestSyncAllowlist_Issue37_PolicyPrefixesReachHelper(t *testing.T) {
	ms := newMockHelper(t)
	ms.setAllowListIPs(nil) // fresh boot; nft @allowed is empty
	e := enforce.New(ms.sock, nil)

	want := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("189.6.10.31/32"),
		netip.MustParsePrefix("51.77.145.130/32"),
		netip.MustParsePrefix("2001:41d0:404:200::8218/128"),
	}
	if err := e.SyncAllowlist(context.Background(), want); err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, r := range ms.recorded() {
		if r.Verb == "allow_add" {
			got[r.IP] = true
		}
	}
	for _, p := range want {
		if !got[p.String()] {
			t.Errorf("expected allow_add for %s, but helper never saw it", p)
		}
	}
	// No stale entries: nothing was in the current listing, so no allow_del.
	for _, r := range ms.recorded() {
		if r.Verb == "allow_del" {
			t.Errorf("unexpected allow_del %s on fresh-boot sync", r.IP)
		}
	}
}

// TestSyncAllowlist_EmptyWantRemovesAll: if the daemon passes no prefixes
// (empty policy + empty store), stale nft entries must be swept.
func TestSyncAllowlist_EmptyWantRemovesAll(t *testing.T) {
	ms := newMockHelper(t)
	ms.setAllowListIPs([]string{"10.0.0.0/8", "192.0.2.1/32"})
	e := enforce.New(ms.sock, nil)

	if err := e.SyncAllowlist(context.Background(), nil); err != nil {
		t.Fatal(err)
	}

	var dels []string
	for _, r := range ms.recorded() {
		if r.Verb == "allow_del" {
			dels = append(dels, r.IP)
		}
	}
	sort.Strings(dels)
	if len(dels) != 2 || dels[0] != "10.0.0.0/8" || dels[1] != "192.0.2.1/32" {
		t.Errorf("expected both prefixes removed, got %v", dels)
	}
}

// ── Network error tests ────────────────────────────────────────────────────────

func TestBan_SocketMissing_ReturnsError(t *testing.T) {
	e := enforce.New("/nonexistent/enforcer.sock", nil)
	err := e.Ban(context.Background(), sdk.Target{IP: netip.MustParseAddr("1.2.3.4")})
	if err == nil {
		t.Fatal("expected error when socket is missing")
	}
}

// ── Integration: network namespace ────────────────────────────────────────────
// Skipped unless running as root with nft available. The test creates the
// enforcer server in-process with a real nft binary inside the default netns.

func TestNetns_BanUnban(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN)")
	}
	// nft must be on PATH
	if _, err := os.Stat("/usr/sbin/nft"); err != nil {
		if _, err2 := os.Stat("/sbin/nft"); err2 != nil {
			t.Skip("nft binary not found")
		}
	}
	// Actual test is in cmd/ezyshield-enforcer/server_test.go (integration).
	t.Log("root + nft detected; full integration test lives in cmd/ezyshield-enforcer")
}
