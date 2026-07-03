package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/enforce"
)

// mockNftCalls records the nft scripts that would be executed.
type mockNftCalls struct {
	scripts []string
}

func (m *mockNftCalls) runner() nftRunner {
	return func(_ context.Context, script []byte) error {
		m.scripts = append(m.scripts, string(script))
		return nil
	}
}

// startTestServer creates a Server with a mock nft runner, starts listening
// on a temp socket, and returns the server (caller must call close).
func startTestServer(t *testing.T, mock *mockNftCalls) *Server {
	t.Helper()
	f, err := os.CreateTemp("", "enforcer-srv-test-*.sock")
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

	run := mock.runner()
	srv := newServer(sockPath, run)

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	srv.ln = ln

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = os.Remove(sockPath)
	})
	go func() { _ = srv.serve(ctx) }() //nolint:errcheck

	return srv
}

func doRPC(t *testing.T, sockPath string, req enforce.Request) enforce.Response {
	t.Helper()
	d := &net.Dialer{}
	conn, err := d.DialContext(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	b, _ := json.Marshal(req)
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}

	var resp enforce.Response
	sc := bufio.NewScanner(conn)
	if sc.Scan() {
		if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return resp
}

// ── verb-level security ────────────────────────────────────────────────────────

func TestDispatch_UnknownVerb_Rejected(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	for _, verb := range []string{"exec", "eval", "nft", "sudo", "", "FLUSH"} {
		resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: verb})
		if resp.OK {
			t.Errorf("verb %q should be rejected, got OK=true", verb)
		}
	}
}

func TestDispatch_Ping(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "ping"})
	if !resp.OK {
		t.Fatalf("ping failed: %s", resp.Error)
	}
}

// ── IP validation ──────────────────────────────────────────────────────────────

func TestDispatch_Add_InvalidIP_Rejected(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	cases := []string{
		"", "not-an-ip", "300.1.2.3", "1.2.3.4; flush table inet filter",
		"../etc/passwd", "::ffff::1",
	}
	for _, ip := range cases {
		resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: ip})
		if resp.OK {
			t.Errorf("IP %q should be rejected, got OK=true", ip)
		}
		// Ensure no nft script was written for the bad IP.
		for _, sc := range mock.scripts {
			if strings.Contains(sc, ip) {
				t.Errorf("bad IP %q appeared in nft script: %s", ip, sc)
			}
		}
	}
}

func TestDispatch_Del_InvalidIP_Rejected(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "del", IP: "not-valid"})
	if resp.OK {
		t.Error("del with invalid IP should be rejected")
	}
}

// ── add / del / list / flush ───────────────────────────────────────────────────

func TestDispatch_Add_ValidIPv4(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "1.2.3.4", TTLSeconds: 300})
	if !resp.OK {
		t.Fatalf("add failed: %s", resp.Error)
	}

	// in-memory state updated
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	if !srv.blocked["1.2.3.4"] {
		t.Error("1.2.3.4 not in in-memory blocked set after add")
	}

	// nft script contained the right element
	if len(mock.scripts) == 0 {
		t.Fatal("expected nft script to be executed")
	}
	last := mock.scripts[len(mock.scripts)-1]
	if !strings.Contains(last, "1.2.3.4") {
		t.Errorf("nft script missing IP: %s", last)
	}
	if !strings.Contains(last, "timeout 300s") {
		t.Errorf("nft script missing timeout: %s", last)
	}
}

func TestDispatch_Add_ValidIPv6(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "2001:db8::1", TTLSeconds: 3600})
	if !resp.OK {
		t.Fatalf("add ipv6 failed: %s", resp.Error)
	}

	if len(mock.scripts) == 0 {
		t.Fatal("expected nft script")
	}
	last := mock.scripts[len(mock.scripts)-1]
	if !strings.Contains(last, "blocked6") {
		t.Errorf("expected IPv6 IP to use blocked6 set: %s", last)
	}
}

func TestDispatch_Add_PermanentBan(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "5.5.5.5", TTLSeconds: 0})
	if !resp.OK {
		t.Fatalf("add permanent failed: %s", resp.Error)
	}

	last := mock.scripts[len(mock.scripts)-1]
	if strings.Contains(last, "timeout") {
		t.Errorf("permanent ban should not contain timeout: %s", last)
	}
}

func TestDispatch_Add_CIDRPrefix(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "10.0.0.0/8", TTLSeconds: 600})
	if !resp.OK {
		t.Fatalf("add CIDR failed: %s", resp.Error)
	}
	last := mock.scripts[len(mock.scripts)-1]
	if !strings.Contains(last, "10.0.0.0/8") {
		t.Errorf("CIDR missing from nft script: %s", last)
	}
}

func TestDispatch_Del_Valid(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	// Pre-populate in-memory state.
	srv.mu.Lock()
	srv.blocked["1.2.3.4"] = true
	srv.mu.Unlock()

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "del", IP: "1.2.3.4"})
	if !resp.OK {
		t.Fatalf("del failed: %s", resp.Error)
	}

	srv.mu.RLock()
	defer srv.mu.RUnlock()
	if srv.blocked["1.2.3.4"] {
		t.Error("1.2.3.4 still in blocked set after del")
	}
}

func TestDispatch_List_ReturnsMemoryState(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	srv.mu.Lock()
	srv.blocked["1.1.1.1"] = true
	srv.blocked["2.2.2.2"] = true
	srv.mu.Unlock()

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "list"})
	if !resp.OK {
		t.Fatalf("list failed: %s", resp.Error)
	}
	sort.Strings(resp.IPs)
	if len(resp.IPs) != 2 || resp.IPs[0] != "1.1.1.1" || resp.IPs[1] != "2.2.2.2" {
		t.Errorf("unexpected list result: %v", resp.IPs)
	}
}

func TestDispatch_Flush_ClearsState(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	srv.mu.Lock()
	srv.blocked["1.1.1.1"] = true
	srv.blocked["2.2.2.2"] = true
	srv.mu.Unlock()

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "flush"})
	if !resp.OK {
		t.Fatalf("flush failed: %s", resp.Error)
	}

	srv.mu.RLock()
	defer srv.mu.RUnlock()
	if len(srv.blocked) != 0 {
		t.Errorf("expected empty blocked set after flush, got %v", srv.blocked)
	}
}

// ── nft script safety: no raw nft syntax in IP field ─────────────────────────

func TestDispatch_Add_RawNftSyntaxInIPField(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	// An attacker might try to inject nft statements via the IP field.
	injections := []string{
		"1.2.3.4 ; flush table inet filter",
		"1.2.3.4\ndelete table inet ezyshield",
		"@blocked",
	}
	for _, ip := range injections {
		resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: ip})
		if resp.OK {
			t.Errorf("injection %q should be rejected", ip)
		}
	}
}

// ── initTable script ─────────────────────────────────────────────────────────

func TestInitTable_BothChainsPresent(t *testing.T) {
	var captured []byte
	run := func(_ context.Context, script []byte) error {
		captured = script
		return nil
	}
	if err := initTable(context.Background(), run); err != nil {
		t.Fatalf("initTable: %v", err)
	}
	s := string(captured)
	for _, want := range []string{
		"hook input",
		"hook forward",
		"hook prerouting",
		"ip saddr @blocked drop",
		"ip6 saddr @blocked6 drop",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("initTable script missing %q\nscript:\n%s", want, s)
		}
	}
	inputIdx := strings.Index(s, "hook input")
	forwardIdx := strings.Index(s, "hook forward")
	if inputIdx < 0 || forwardIdx < 0 {
		t.Fatal("missing input or forward hook declaration")
	}
}

// TestInitTable_PreroutingSinkhole validates the raw/prerouting chain from
// issue #23: correct priority, allowlist rules come BEFORE blocklist (the
// anti-lockout invariant per AGENTS.md §2), notrack precedes drop for
// conntrack economy under scanner floods.
func TestInitTable_PreroutingSinkhole(t *testing.T) {
	var captured []byte
	run := func(_ context.Context, script []byte) error {
		captured = script
		return nil
	}
	if err := initTable(context.Background(), run); err != nil {
		t.Fatalf("initTable: %v", err)
	}
	s := string(captured)

	if !strings.Contains(s, "hook prerouting priority raw") {
		t.Errorf("prerouting chain not at priority raw:\n%s", s)
	}
	if !strings.Contains(s, "add set inet ezyshield allowed ") ||
		!strings.Contains(s, "add set inet ezyshield allowed6 ") {
		t.Errorf("initTable missing @allowed sets:\n%s", s)
	}
	preroutingBlock := s[strings.Index(s, "flush chain inet ezyshield prerouting"):]
	allowIdx := strings.Index(preroutingBlock, "@allowed accept")
	notrackIdx := strings.Index(preroutingBlock, "@blocked notrack")
	dropIdx := strings.Index(preroutingBlock, "@blocked drop")
	if allowIdx < 0 || notrackIdx < 0 || dropIdx < 0 {
		t.Fatalf("prerouting rules missing:\n%s", preroutingBlock)
	}
	if allowIdx >= notrackIdx || notrackIdx >= dropIdx {
		t.Errorf("prerouting rule order wrong: allow=%d notrack=%d drop=%d\n%s",
			allowIdx, notrackIdx, dropIdx, preroutingBlock)
	}
}

// TestDispatch_AllowAdd covers the "allow_add" verb.
func TestDispatch_AllowAdd(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "allow_add", IP: "10.0.0.0/8"})
	if !resp.OK {
		t.Fatalf("allow_add failed: %s", resp.Error)
	}
	if len(mock.scripts) == 0 {
		t.Fatal("expected nft script")
	}
	last := mock.scripts[len(mock.scripts)-1]
	if !strings.Contains(last, "10.0.0.0/8") || !strings.Contains(last, "allowed") {
		t.Errorf("nft script wrong shape: %s", last)
	}
}

// TestDispatch_AllowDel covers the "allow_del" verb.
func TestDispatch_AllowDel(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "allow_del", IP: "10.0.0.0/8"})
	if !resp.OK {
		t.Fatalf("allow_del failed: %s", resp.Error)
	}
	last := mock.scripts[len(mock.scripts)-1]
	if !strings.Contains(last, "delete element") || !strings.Contains(last, "allowed") {
		t.Errorf("nft script wrong shape: %s", last)
	}
}

// TestAllowSetForIP: v4 vs v6 routing.
func TestAllowSetForIP(t *testing.T) {
	if s, err := allowSetForIP("1.2.3.4"); err != nil || s != nftSetAllow4 {
		t.Errorf("v4: got %s err=%v", s, err)
	}
	if s, err := allowSetForIP("::1"); err != nil || s != nftSetAllow6 {
		t.Errorf("v6: got %s err=%v", s, err)
	}
	if _, err := allowSetForIP("not-an-ip"); err == nil {
		t.Error("expected error for invalid IP")
	}
}

// ── nft helpers ───────────────────────────────────────────────────────────────

func TestSetForIP_IPv4(t *testing.T) {
	set, err := setForIP("1.2.3.4")
	if err != nil || set != nftSet4 {
		t.Errorf("expected %s, got %s (err=%v)", nftSet4, set, err)
	}
}

func TestSetForIP_IPv6(t *testing.T) {
	set, err := setForIP("::1")
	if err != nil || set != nftSet6 {
		t.Errorf("expected %s, got %s (err=%v)", nftSet6, set, err)
	}
}

func TestSetForIP_InvalidRejected(t *testing.T) {
	_, err := setForIP("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestParseSetElements(t *testing.T) {
	out := []byte(`table inet ezyshield {
    set blocked {
        type ipv4_addr
        flags interval, timeout
        auto-merge
        elements = { 1.2.3.4 timeout 5m0s expires 4m55s,
                     5.6.7.8 }
    }
}`)
	got := parseSetElements(out)
	sort.Strings(got)
	want := []string{"1.2.3.4", "5.6.7.8"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] expected %s, got %s", i, want[i], got[i])
		}
	}
}

func TestParseSetElements_Empty(t *testing.T) {
	out := []byte(`table inet ezyshield {
    set blocked {
        type ipv4_addr
        flags interval, timeout
        auto-merge
    }
}`)
	got := parseSetElements(out)
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

// ── nftDel "not found" idempotency (issue #38) ───────────────────────────────

func TestNftDel_NotFoundInSet_Ignored(t *testing.T) {
	for _, errMsg := range []string{
		"Error: interval not found in set\ndelete element inet ezyshield blocked { 1.2.3.4 }",
		"nft -f: exit status 1\nError: No such file or directory; did you mean table 'ezyshield' in family inet?",
	} {
		captured := errMsg
		run := func(_ context.Context, _ []byte) error {
			return fmt.Errorf("%s", captured)
		}
		if err := nftDel(context.Background(), run, "1.2.3.4"); err != nil {
			t.Errorf("expected nil for %q, got: %v", errMsg, err)
		}
	}
}

func TestNftDel_OtherError_Propagated(t *testing.T) {
	run := func(_ context.Context, _ []byte) error {
		return fmt.Errorf("nft -f: exit status 1\npermission denied")
	}
	if err := nftDel(context.Background(), run, "1.2.3.4"); err == nil {
		t.Error("expected error to propagate, got nil")
	}
}

// ── socket permissions (issue #92) ──────────────────────────────────────────

// TestListen_SocketPermissions verifies that after listen() the unix socket
// is created with mode 0660 (owner rw, group rw, other none). Chown to the
// ezyshield group is best-effort and not asserted here because CI test runners
// rarely have the group present.
func TestListen_SocketPermissions(t *testing.T) {
	sockPath := t.TempDir() + "/enforcer.sock"

	srv := newServer(sockPath, (&mockNftCalls{}).runner())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.listen(ctx); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.ln.Close() //nolint:errcheck

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Errorf("path is not a unix socket: mode=%v", info.Mode())
	}
	gotPerm := info.Mode().Perm()
	const wantPerm = os.FileMode(0o660)
	if gotPerm != wantPerm {
		t.Errorf("socket perms: got %04o, want %04o", gotPerm, wantPerm)
	}
}

// ── integration: skip if no root/nft ─────────────────────────────────────────

func TestIntegration_BanUnban(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN)")
	}
	nftPath := "/usr/sbin/nft"
	if _, err := os.Stat(nftPath); err != nil {
		if _, err2 := os.Stat("/sbin/nft"); err2 != nil {
			t.Skip("nft binary not found")
		}
	}

	// Use real nft runner; nft will modify the host netns.
	// This test is intentionally guarded: it only runs as root with nft present.
	ctx := context.Background()
	srv := newServer("", realNftRunner)
	srv.blocked = make(map[string]bool)

	// init: create the table/set/chain
	if err := srv.init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	t.Cleanup(func() {
		// Remove the test table to leave no trace.
		_ = exec.CommandContext(context.Background(), "nft", "delete", "table", "inet", "ezyshield").Run() //nolint:gosec // constant args
	})

	ip := "198.51.100.1" // TEST-NET-2, should not affect anything real

	// add
	resp := srv.dispatch(ctx, enforce.Request{Verb: "add", IP: ip, TTLSeconds: 30})
	if !resp.OK {
		t.Fatalf("add: %s", resp.Error)
	}
	// list
	resp = srv.dispatch(ctx, enforce.Request{Verb: "list"})
	if !resp.OK || len(resp.IPs) == 0 {
		t.Fatalf("list after add: %+v", resp)
	}
	// del
	resp = srv.dispatch(ctx, enforce.Request{Verb: "del", IP: ip})
	if !resp.OK {
		t.Fatalf("del: %s", resp.Error)
	}
	resp = srv.dispatch(ctx, enforce.Request{Verb: "list"})
	if !resp.OK {
		t.Fatalf("list after del: %s", resp.Error)
	}
	for _, got := range resp.IPs {
		if got == ip {
			t.Errorf("IP %s still present after del", ip)
		}
	}
}
