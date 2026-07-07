package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
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
	// Default to a no-op ssRunner so tests do not shell out to a real
	// `ss -K` on the host during add verb coverage. Individual tests that
	// need to assert kill-behaviour override srv.runSs after construction.
	srv.runSs = func(_ context.Context, _ []string) error { return nil }

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

// ── nftDel already-absent signalling (issues #38, #39) ──────────────────────

// TestNftDel_ElementAbsent_ReturnsSentinel asserts that every known nft
// "already gone" stderr variant is translated to the errElementAbsent
// sentinel — never propagated as a raw wrapped error. This is the single
// place in the codebase where nft's free-form stderr is inspected; if a new
// wording surfaces in the wild, extend nftAbsentSignals here rather than
// string-matching downstream (issue #39, Hard Rule §5).
func TestNftDel_ElementAbsent_ReturnsSentinel(t *testing.T) {
	cases := []struct {
		name   string
		nftErr string
	}{
		{
			name:   "not_found_in_set (older nft)",
			nftErr: "Error: interval not found in set\ndelete element inet ezyshield blocked { 1.2.3.4 }",
		},
		{
			name:   "no_such_file_or_directory (set missing)",
			nftErr: "nft -f: exit status 1\nError: No such file or directory; did you mean table 'ezyshield' in family inet?",
		},
		{
			// The live variant from issue #39 (nftables 1.0+ / current Debian
			// / Ubuntu). This is the wording that was noise-flooding the
			// kylian-s host every ban-expiry tick.
			name:   "element_does_not_exist (nftables 1.0+, live host)",
			nftErr: "nft -f: exit status 1\n/tmp/ezyshield-enforcer-XXX.nft:1:41-54: Error: element does not exist\ndelete element inet ezyshield blocked { 198.51.100.212 }",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			captured := tc.nftErr
			run := func(_ context.Context, _ []byte) error {
				return fmt.Errorf("%s", captured)
			}
			err := nftDel(context.Background(), run, "1.2.3.4")
			if !errors.Is(err, errElementAbsent) {
				t.Errorf("expected errElementAbsent, got: %v", err)
			}
		})
	}
}

func TestNftDel_OtherError_Propagated(t *testing.T) {
	run := func(_ context.Context, _ []byte) error {
		return fmt.Errorf("nft -f: exit status 1\npermission denied")
	}
	err := nftDel(context.Background(), run, "1.2.3.4")
	if err == nil {
		t.Fatal("expected error to propagate, got nil")
	}
	if errors.Is(err, errElementAbsent) {
		t.Errorf("permission-denied must NOT be classified as absent, got: %v", err)
	}
}

// TestNftDelAllow_ElementAbsent_ReturnsSentinel mirrors the block-set fix
// for the allow-set delete path (issue #39, §5). Kept in step with nftDel
// so the two never diverge.
func TestNftDelAllow_ElementAbsent_ReturnsSentinel(t *testing.T) {
	run := func(_ context.Context, _ []byte) error {
		return fmt.Errorf("nft -f: exit status 1\nError: element does not exist")
	}
	err := nftDelAllow(context.Background(), run, "10.0.0.0/8")
	if !errors.Is(err, errElementAbsent) {
		t.Errorf("expected errElementAbsent from nftDelAllow, got: %v", err)
	}
}

// TestDispatch_Del_AlreadyAbsent_TypedCode locks in the wire-format contract
// from issue #39: when the helper detects the target was already gone, it
// returns OK=true with Code=already_absent. The Error field MUST stay empty
// so the client never sees nft's stderr text (that's the whole point of the
// refactor — the client is not allowed to depend on nft's error wording).
func TestDispatch_Del_AlreadyAbsent_TypedCode(t *testing.T) {
	nftFail := func(_ context.Context, _ []byte) error {
		return fmt.Errorf("nft -f: exit status 1\nError: element does not exist")
	}
	f, err := os.CreateTemp("", "enforcer-srv-test-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	sockPath := f.Name()
	_ = f.Close()
	_ = os.Remove(sockPath)

	srv := newServer(sockPath, nftFail)
	srv.runSs = func(_ context.Context, _ []string) error { return nil }
	// Pre-populate the in-memory cache to prove the already-absent branch
	// still evicts the entry (otherwise Sync would keep retrying every tick).
	srv.blocked["1.2.3.4"] = true

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	srv.ln = ln
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = os.Remove(sockPath) })
	go func() { _ = srv.serve(ctx) }() //nolint:errcheck

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "del", IP: "1.2.3.4"})
	if !resp.OK {
		t.Fatalf("expected OK=true for already-absent, got OK=false Error=%q", resp.Error)
	}
	if resp.Code != enforce.CodeAlreadyAbsent {
		t.Errorf("expected Code=%q, got %q", enforce.CodeAlreadyAbsent, resp.Code)
	}
	if resp.Error != "" {
		t.Errorf("Error must be empty for already-absent success (nft stderr must not leak to client), got: %q", resp.Error)
	}
	srv.mu.RLock()
	still := srv.blocked["1.2.3.4"]
	srv.mu.RUnlock()
	if still {
		t.Error("in-memory blocked cache still contains 1.2.3.4 after already-absent del")
	}
}

// TestDispatch_Del_RealError_NoTypedCode: a permission-denied (or any other
// real failure) MUST surface as OK=false with the error text. No stable code
// is set, so a future refactor can't accidentally silence real failures.
func TestDispatch_Del_RealError_NoTypedCode(t *testing.T) {
	nftFail := func(_ context.Context, _ []byte) error {
		return fmt.Errorf("nft -f: exit status 1\npermission denied")
	}
	f, err := os.CreateTemp("", "enforcer-srv-test-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	sockPath := f.Name()
	_ = f.Close()
	_ = os.Remove(sockPath)

	srv := newServer(sockPath, nftFail)
	srv.runSs = func(_ context.Context, _ []string) error { return nil }

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	srv.ln = ln
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = os.Remove(sockPath) })
	go func() { _ = srv.serve(ctx) }() //nolint:errcheck

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "del", IP: "1.2.3.4"})
	if resp.OK {
		t.Fatal("expected OK=false for permission-denied, got OK=true")
	}
	if resp.Code == enforce.CodeAlreadyAbsent {
		t.Errorf("permission-denied must NOT return CodeAlreadyAbsent; got Code=%q", resp.Code)
	}
	if resp.Error == "" {
		t.Error("expected non-empty Error for real failure")
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

// ── pre-ban TCP session teardown wiring (issue #30) ──────────────────────────

// TestDispatch_AddInvokesNftAddThenKill verifies that a valid single-address
// ban runs nft first and then `ss -K`, in that order. The order matters: the
// nft rule must be committed before the teardown so a client that reconnects
// mid-teardown is caught by the drop.
func TestDispatch_AddInvokesNftAddThenKill(t *testing.T) {
	nftMock := &mockNftCalls{}
	srv := startTestServer(t, nftMock)

	ssMock := &mockSsCalls{}
	srv.runSs = ssMock.runner()

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "1.2.3.4", TTLSeconds: 300})
	if !resp.OK {
		t.Fatalf("add failed: %s", resp.Error)
	}

	if len(nftMock.scripts) == 0 {
		t.Fatal("expected nftAdd to have been called")
	}
	if len(ssMock.calls) != 1 {
		t.Fatalf("expected exactly 1 ss call, got %d", len(ssMock.calls))
	}
	wantSsArgs := []string{"-K", "dst", "1.2.3.4"}
	if !reflect.DeepEqual(ssMock.calls[0], wantSsArgs) {
		t.Errorf("ss args: got %v, want %v", ssMock.calls[0], wantSsArgs)
	}
	// nftAdd script content sanity: contains the IP, so we know it ran with
	// the right target. Order-of-invocation is guaranteed by the synchronous
	// dispatch path — ss only runs if nftAdd returned nil.
	if !strings.Contains(nftMock.scripts[0], "1.2.3.4") {
		t.Errorf("nft script did not contain the target IP: %s", nftMock.scripts[0])
	}
}

// TestDispatch_AddSkipsKillForCIDR asserts that ss -K is NOT invoked when the
// ban target is a prefix. `ss -K dst` takes a single address; a /24 ban would
// otherwise need per-address fan-out which is out of scope for this fix
// (tracked as CIDR follow-up in issue #30).
func TestDispatch_AddSkipsKillForCIDR(t *testing.T) {
	nftMock := &mockNftCalls{}
	srv := startTestServer(t, nftMock)

	ssMock := &mockSsCalls{}
	srv.runSs = ssMock.runner()

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "10.0.0.0/24", TTLSeconds: 600})
	if !resp.OK {
		t.Fatalf("add CIDR failed: %s", resp.Error)
	}

	if len(ssMock.calls) != 0 {
		t.Errorf("ss -K must not be invoked for CIDR bans, got calls: %v", ssMock.calls)
	}
}

// TestDispatch_AllowAddDoesNotKill guards against a wiring mistake where the
// kill helper leaks into the allowlist path. Allowlist adds have nothing to
// tear down — the peer is *authorised*, not banned.
func TestDispatch_AllowAddDoesNotKill(t *testing.T) {
	nftMock := &mockNftCalls{}
	srv := startTestServer(t, nftMock)

	ssMock := &mockSsCalls{}
	srv.runSs = ssMock.runner()

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "allow_add", IP: "1.2.3.4"})
	if !resp.OK {
		t.Fatalf("allow_add failed: %s", resp.Error)
	}

	if len(ssMock.calls) != 0 {
		t.Errorf("ss -K must not be invoked for allow_add, got calls: %v", ssMock.calls)
	}
}

// TestDispatch_AddNftFailure_SkipsKill: if nftAdd returns an error the ban is
// not committed and the RPC returns OK=false. In that case ss -K MUST NOT run
// — killing sockets for an IP we failed to ban would be a user-visible
// side-effect with no matching firewall rule.
func TestDispatch_AddNftFailure_SkipsKill(t *testing.T) {
	// Nft runner that always fails.
	failing := func(_ context.Context, _ []byte) error {
		return fmt.Errorf("nft -f: exit status 1\nsimulated failure")
	}
	f, err := os.CreateTemp("", "enforcer-srv-test-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	sockPath := f.Name()
	_ = f.Close()
	_ = os.Remove(sockPath)

	srv := newServer(sockPath, failing)
	ssMock := &mockSsCalls{}
	srv.runSs = ssMock.runner()

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	srv.ln = ln
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = os.Remove(sockPath) })
	go func() { _ = srv.serve(ctx) }() //nolint:errcheck

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "1.2.3.4"})
	if resp.OK {
		t.Fatalf("expected add to fail when nft fails, got OK")
	}
	if len(ssMock.calls) != 0 {
		t.Errorf("ss -K must not be invoked when nftAdd fails, got calls: %v", ssMock.calls)
	}
}
