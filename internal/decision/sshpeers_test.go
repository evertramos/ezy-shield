package decision

// Tests for the /proc-based SSH peer detection (issue #175), exercising the
// parser against fixture files instead of the environment: v4, v6,
// IPv6-mapped addresses, non-default sshd ports, and hostile content.

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func scanFixture(t *testing.T, path string) *bufio.Scanner {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return bufio.NewScanner(f)
}

func TestParseProcTCPPeers_V4Fixture(t *testing.T) {
	t.Parallel()
	ports := map[uint16]bool{22: true}
	peers := parseProcTCPPeers(scanFixture(t, "testdata/proc_net_tcp"), ports)

	// Exactly one peer: the ESTABLISHED remote on local port 22.
	// LISTEN (0A), a different local port (80), a non-ESTABLISHED state
	// (06), the malformed hex line, and the garbage line contribute nothing.
	want := netip.MustParseAddr("198.51.100.23")
	if len(peers) != 1 || peers[0] != want {
		t.Fatalf("peers = %v, want [%s]", peers, want)
	}
}

func TestParseProcTCPPeers_V6FixtureIncludingMapped(t *testing.T) {
	t.Parallel()
	ports := map[uint16]bool{22: true}
	peers := parseProcTCPPeers(scanFixture(t, "testdata/proc_net_tcp6"), ports)

	if len(peers) != 2 {
		t.Fatalf("peers = %v, want 2 entries", peers)
	}
	if want := netip.MustParseAddr("2001:db8::7"); peers[0] != want {
		t.Errorf("peers[0] = %s, want %s", peers[0], want)
	}
	// The IPv4-mapped peer must be unmapped so it compares equal to the
	// plain IPv4 form a verdict carries.
	if want := netip.MustParseAddr("203.0.113.5"); peers[1] != want {
		t.Errorf("peers[1] = %s, want unmapped %s", peers[1], want)
	}
	if peers[1].Is4In6() {
		t.Error("mapped peer was not unmapped")
	}
}

func TestParseProcTCPPeers_NonDefaultPort(t *testing.T) {
	t.Parallel()
	// With only port 2222 in the set, the port-22 rows must not match.
	peers := parseProcTCPPeers(scanFixture(t, "testdata/proc_net_tcp"), map[uint16]bool{2222: true})
	if len(peers) != 0 {
		t.Fatalf("peers = %v, want none for port 2222", peers)
	}
}

func TestParseProcTCPPeers_GarbageNeverPanics(t *testing.T) {
	t.Parallel()
	peers := parseProcTCPPeers(scanFixture(t, "testdata/proc_net_tcp_garbage"), map[uint16]bool{22: true})
	if len(peers) != 0 {
		t.Fatalf("garbage produced peers: %v", peers)
	}
}

func TestSshdPorts(t *testing.T) {
	t.Parallel()
	ports := sshdPorts("testdata/sshd_config_custom")
	if !ports[2222] || !ports[22022] || len(ports) != 2 {
		t.Errorf("ports = %v, want {2222,22022} (Port directives, case-insensitive)", ports)
	}
	// Documented fallback: missing file → 22.
	if ports := sshdPorts("testdata/does-not-exist"); !ports[22] || len(ports) != 1 {
		t.Errorf("missing config: ports = %v, want {22}", ports)
	}
}

func TestSSHPeerCache_TTL(t *testing.T) {
	t.Parallel()
	calls := 0
	c := &sshPeerCache{probe: func() []netip.Addr {
		calls++
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	}}
	_ = c.get()
	_ = c.get()
	if calls != 1 {
		t.Errorf("probe calls = %d, want 1 (second get inside TTL)", calls)
	}
	c.fetched = time.Now().Add(-2 * sshPeerCacheTTL)
	_ = c.get()
	if calls != 2 {
		t.Errorf("probe calls = %d, want 2 after TTL expiry", calls)
	}
}

// FuzzProcTCPPeers keeps the proc parser panic-free on hostile bytes
// (repo gate convention: every new parser gets a fuzz target with
// malformed, oversized, binary, ANSI, and CRLF seeds).
func FuzzProcTCPPeers(f *testing.F) {
	f.Add("   1: 0100007F:0016 176433C6:D2F0 01 rest")
	f.Add("   1: 00000000000000000000000001000000:0016 B80D0120000000000000000007000000:E1F2 01 x")
	f.Add("sl local rem st")
	f.Add("1: :0016 :FFFF 01")
	f.Add("1: ZZZZZZZZ:GGGG QQQQQQQQ:0016 01")
	f.Add(strings.Repeat("A", 8192) + ":0016 " + strings.Repeat("F", 8192) + ":0016 01")
	f.Add("\x1b[31m1: 0100007F:0016 176433C6:D2F0 01\x1b[0m")
	f.Add("1: 0100007F:0016 176433C6:D2F0 01\r\n2: garbage")
	f.Add("\x00\xff\xfe binary")
	f.Fuzz(func(t *testing.T, line string) {
		sc := bufio.NewScanner(strings.NewReader(line))
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		_ = parseProcTCPPeers(sc, map[uint16]bool{22: true, 2222: true})
	})
}
