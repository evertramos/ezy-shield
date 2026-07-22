package decision

// sshpeers.go — SSH peer detection that works under systemd (issue #175).
//
// The anti-lockout check historically derived the current SSH peer from the
// SSH_CLIENT environment variable, which exists in an interactive shell but
// NOT when the daemon runs as a systemd service — in production the
// protection found no peer at all. This file derives peers from the kernel
// instead: remote addresses of ESTABLISHED sockets on the sshd listen
// port(s), read from /proc/net/tcp and /proc/net/tcp6 (world-readable, no
// privileges, no shelling out). SSH_CLIENT remains an extra source for
// interactive contexts; the daemon path does not depend on it.
//
// The proc files are kernel-generated, but the parser still treats them as
// untrusted bytes (Hard Rule §4 discipline): every field is length- and
// hex-checked, malformed lines are skipped, and FuzzProcTCPPeers keeps the
// whole path panic-free on hostile input.

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default locations; vars so tests point them at fixtures.
var (
	procTCPPaths   = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	sshdConfigPath = "/etc/ssh/sshd_config"
)

// procTCPEstablished is the kernel's TCP_ESTABLISHED state in /proc/net/tcp.
const procTCPEstablished = "01"

// sshPeerCacheTTL bounds how often the proc files are re-read on the hot
// decision path. Two seconds keeps a freshly opened SSH session protected
// well before any realistic detection-to-ban latency, at ~zero cost.
const sshPeerCacheTTL = 2 * time.Second

// ProcSSHPeers returns the remote addresses of established inbound
// connections to the local sshd port(s), best-effort: any unreadable file
// or unparsable content contributes nothing (never an error — the caller
// treats "no peers found" and "could not read" identically, and the
// allowlist/admin_cidrs remain the operator's durable protection).
//
// sshd ports come from the Port directives in /etc/ssh/sshd_config, with a
// documented fallback to 22 when the file is missing, unreadable, or
// declares no Port.
func ProcSSHPeers() []netip.Addr {
	ports := sshdPorts(sshdConfigPath)
	var peers []netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, path := range procTCPPaths {
		f, err := os.Open(path) //nolint:gosec // fixed kernel paths (or test fixtures)
		if err != nil {
			continue
		}
		for _, p := range parseProcTCPPeers(bufio.NewScanner(f), ports) {
			if !seen[p] {
				seen[p] = true
				peers = append(peers, p)
			}
		}
		_ = f.Close()
	}
	return peers
}

// sshdPorts parses the Port directives from an sshd_config. Multiple Port
// lines are all honored (sshd listens on each). Fallback: port 22 when the
// file is missing or has no valid Port directive. ListenAddress port
// suffixes are intentionally not parsed — Port directives plus the :22
// fallback cover the documented behavior; exotic setups get protection via
// admin_cidrs.
func sshdPorts(path string) map[uint16]bool {
	ports := make(map[uint16]bool)
	f, err := os.Open(path) //nolint:gosec // fixed config path (or test fixture)
	if err != nil {
		return map[uint16]bool{22: true}
	}
	defer f.Close() //nolint:errcheck // read-only

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Port") {
			continue
		}
		if n, err := strconv.ParseUint(fields[1], 10, 16); err == nil && n > 0 {
			ports[uint16(n)] = true
		}
	}
	if len(ports) == 0 {
		return map[uint16]bool{22: true}
	}
	return ports
}

// parseProcTCPPeers extracts remote peer addresses of ESTABLISHED sockets
// whose LOCAL port is one of ports, from a /proc/net/tcp(6) style stream.
//
// Line shape (both files):
//
//	sl  local_address rem_address   st ...
//	0: 0100007F:0016 C0A80001:D2F0 01 ...
//
// Addresses are hex; each 32-bit group is in host (little-endian) byte
// order, ports are big-endian hex. Malformed lines are skipped — never an
// error, never a panic (fuzz-guarded).
func parseProcTCPPeers(sc *bufio.Scanner, ports map[uint16]bool) []netip.Addr {
	var peers []netip.Addr
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// fields: [0]=sl [1]=local [2]=remote [3]=state ...
		if len(fields) < 4 || fields[3] != procTCPEstablished {
			continue
		}
		localPort, ok := procPort(fields[1])
		if !ok || !ports[localPort] {
			continue
		}
		if addr, ok := procAddr(fields[2]); ok {
			peers = append(peers, addr)
		}
	}
	return peers
}

// procPort extracts the big-endian hex port from an "ADDR:PORT" field.
func procPort(field string) (uint16, bool) {
	i := strings.LastIndexByte(field, ':')
	if i < 0 || len(field)-i-1 != 4 {
		return 0, false
	}
	n, err := strconv.ParseUint(field[i+1:], 16, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

// procAddr decodes the address half of an "ADDR:PORT" field: 8 hex chars
// for IPv4, 32 for IPv6, each 4-byte word little-endian. IPv4-mapped IPv6
// addresses are unmapped so they compare equal to plain IPv4 peers.
func procAddr(field string) (netip.Addr, bool) {
	i := strings.LastIndexByte(field, ':')
	if i < 0 {
		return netip.Addr{}, false
	}
	raw, err := hex.DecodeString(field[:i])
	if err != nil {
		return netip.Addr{}, false
	}
	switch len(raw) {
	case 4:
		return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), true
	case 16:
		var b [16]byte
		for g := 0; g < 4; g++ {
			for k := 0; k < 4; k++ {
				b[g*4+k] = raw[g*4+(3-k)]
			}
		}
		return netip.AddrFrom16(b).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// sshPeerCache is the engine-side TTL cache over ProcSSHPeers so the hot
// Decide path does not re-read /proc on every verdict.
type sshPeerCache struct {
	mu      sync.Mutex
	probe   func() []netip.Addr // ProcSSHPeers; swappable in tests
	fetched time.Time
	peers   []netip.Addr
}

func (c *sshPeerCache) get() []netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.probe == nil {
		c.probe = ProcSSHPeers
	}
	if time.Since(c.fetched) > sshPeerCacheTTL {
		c.peers = c.probe()
		c.fetched = time.Now()
	}
	return c.peers
}

// activeSSHPeers returns every currently known operator SSH peer: the
// SSH_CLIENT-derived one (interactive contexts, re-read per call) plus the
// kernel-derived set (the path that works under systemd, TTL-cached).
func (e *Engine) activeSSHPeers() []netip.Addr {
	var peers []netip.Addr
	if p := sshClientIP(); p.IsValid() {
		peers = append(peers, p)
	}
	return append(peers, e.sshPeers.get()...)
}

// SetSSHPeerProbe replaces the kernel peer probe (tests; a future platform
// abstraction). It never weakens anything by itself: the probe's results
// only ever ADD refusals to ban decisions.
func (e *Engine) SetSSHPeerProbe(fn func() []netip.Addr) {
	e.sshPeers.mu.Lock()
	defer e.sshPeers.mu.Unlock()
	e.sshPeers.probe = fn
	e.sshPeers.fetched = time.Time{}
}
