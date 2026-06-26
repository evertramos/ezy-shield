// Package scan discovers listening TCP sockets via /proc/net/tcp[6], maps
// each to its owning process / systemd unit / container, and resolves a log
// source. Public listeners with no resolvable log source are flagged ⚠ no logs.
//
// /proc reads are untrusted only in the sense that the kernel can return
// arbitrary data if the PID vanishes mid-scan; all fields are bounded and
// validated before use (Hard Rule §4 from AGENTS.md does not apply here
// because we never interpolate these values into shell commands or SQL).
package scan

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const tcpStateListen = 0x0A

// Listener represents one listening TCP socket and its enriched metadata.
type Listener struct {
	Addr     netip.AddrPort
	Protocol string // "tcp" | "tcp6"
	UID      uint32
	Inode    uint64

	PID      int    // 0 if PID resolution failed (race: process may have exited)
	ExePath  string // resolved from /proc/PID/exe
	UserName string // resolved from /etc/passwd

	IsPublic bool // true when bound to a non-loopback / non-RFC1918 addr or 0.0.0.0/::

	OwnerType      string // "systemd" | "docker" | "unknown"
	UnitName       string // systemd unit (e.g. "nginx.service")
	ContainerID    string // Docker/Podman container ID (full SHA)
	ContainerName  string // container name (populated by InspectContainer)
	ContainerImage string // image name (populated by InspectContainer)

	// LogSource is "journald://UNIT", an absolute file path, or "⚠ no logs"
	// (for public listeners where no log source could be resolved).
	LogSource string
}

// ContainerInfo is returned by InspectContainer to describe logging for a container.
type ContainerInfo struct {
	Name      string
	Image     string
	LogDriver string // "json-file", "journald", "none", ...
	LogPath   string // absolute path when LogDriver == "json-file"
	UnitName  string // journald unit name when LogDriver == "journald"
}

// Sources provides data inputs for the Scanner. Zero value uses real /proc
// and /etc/passwd. Inject non-nil fields for hermetic tests.
type Sources struct {
	NetTCPPath  string // default: /proc/net/tcp
	NetTCP6Path string // default: /proc/net/tcp6
	ProcDir     string // default: /proc  (scanned to map inodes → PIDs)
	PasswdPath  string // default: /etc/passwd

	// NetTCPReader / NetTCP6Reader, when non-nil, are read instead of opening
	// the corresponding path. Used by tests to inject fixture content.
	NetTCPReader  io.Reader
	NetTCP6Reader io.Reader

	// InodeResolver, when non-nil, maps a socket inode to (pid, exePath,
	// cgroupFileContent). Nil = scan /proc/<pid>/fd/ entries (real /proc).
	InodeResolver func(inode uint64) (pid int, exePath string, cgroupContent string)

	// UserLookup, when non-nil, resolves a UID to a username.
	// Nil = parse PasswdPath.
	UserLookup func(uid uint32) string

	// InspectContainer, when non-nil, is called for each Docker container ID
	// found in a cgroup path to retrieve name, image, and logging config.
	// Nil = skip docker inspection (LogSource falls back to "⚠ no logs").
	InspectContainer func(ctx context.Context, id string) (*ContainerInfo, error)
}

// Scanner discovers and enriches listening sockets.
type Scanner struct {
	src Sources
}

// New returns a Scanner backed by src. Zero Sources{} reads from real /proc.
func New(src Sources) *Scanner {
	if src.NetTCPPath == "" {
		src.NetTCPPath = "/proc/net/tcp"
	}
	if src.NetTCP6Path == "" {
		src.NetTCP6Path = "/proc/net/tcp6"
	}
	if src.ProcDir == "" {
		src.ProcDir = "/proc"
	}
	if src.PasswdPath == "" {
		src.PasswdPath = "/etc/passwd"
	}
	return &Scanner{src: src}
}

// Scan returns all currently listening sockets with enriched metadata.
// IPv6 errors are non-fatal: if /proc/net/tcp6 is absent the scan continues
// with IPv4-only results and a warning log.
func (sc *Scanner) Scan(ctx context.Context) ([]Listener, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	v4, err := sc.readTCP(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("scan tcp: %w", err)
	}
	v6, err := sc.readTCP(ctx, true)
	if err != nil {
		slog.WarnContext(ctx, "scan: /proc/net/tcp6 unavailable", "err", err)
	}

	listeners := append(v4, v6...) //nolint:gocritic // intentional pre-alloc free append

	userCache := sc.buildUserCache()
	for i := range listeners {
		if ctx.Err() != nil {
			break
		}
		l := &listeners[i]
		pid, exe, cgroup := sc.resolveInode(l.Inode)
		l.PID = pid
		l.ExePath = exe
		l.UserName = sc.resolveUser(l.UID, userCache)
		l.IsPublic = ClassifyPublic(l.Addr.Addr())
		l.OwnerType, l.UnitName, l.ContainerID = ParseCgroupOwner(cgroup)
		l.LogSource = sc.resolveLogSource(ctx, l)
	}

	return listeners, nil
}

// readTCP reads either /proc/net/tcp (ipv6=false) or /proc/net/tcp6 and
// returns only entries in TCP_LISTEN state.
func (sc *Scanner) readTCP(ctx context.Context, ipv6 bool) ([]Listener, error) {
	proto := "tcp"
	if ipv6 {
		proto = "tcp6"
	}

	var r io.Reader
	if ipv6 {
		r = sc.src.NetTCP6Reader
	} else {
		r = sc.src.NetTCPReader
	}

	if r == nil {
		path := sc.src.NetTCPPath
		if ipv6 {
			path = sc.src.NetTCP6Path
		}
		f, err := os.Open(path) //nolint:gosec // path is admin-controlled (/proc/net/tcp[6])
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}

	return parseProcNetTCP(ctx, r, proto)
}

// parseProcNetTCP parses the content of /proc/net/tcp[6] and returns LISTEN
// entries. Malformed lines are skipped with a debug log; they never panic.
func parseProcNetTCP(ctx context.Context, r io.Reader, proto string) ([]Listener, error) {
	ipv6 := proto == "tcp6"
	var out []Listener

	sc := bufio.NewScanner(r)
	sc.Scan() // skip header line

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			slog.DebugContext(ctx, "scan: short /proc/net/tcp line", "line", line)
			continue
		}

		// fields[3] is the connection state in hex; keep only LISTEN.
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil || state != tcpStateListen {
			continue
		}

		ap, err := parseHexAddrPort(fields[1], ipv6)
		if err != nil {
			slog.DebugContext(ctx, "scan: bad addr:port", "field", fields[1], "err", err)
			continue
		}

		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			slog.DebugContext(ctx, "scan: bad uid", "field", fields[7])
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			slog.DebugContext(ctx, "scan: bad inode", "field", fields[9])
			continue
		}

		out = append(out, Listener{
			Addr:     ap,
			Protocol: proto,
			UID:      uint32(uid),
			Inode:    inode,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanning %s: %w", proto, err)
	}
	return out, nil
}

// parseHexAddrPort converts the "HEXIP:HEXPORT" field from /proc/net/tcp[6]
// into a netip.AddrPort. IPv4 addresses are stored as LE uint32; IPv6 as four
// LE uint32 groups (kernel host-byte-order representation).
func parseHexAddrPort(s string, ipv6 bool) (netip.AddrPort, error) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return netip.AddrPort{}, fmt.Errorf("no colon in %q", s)
	}
	addrHex := s[:idx]
	portHex := s[idx+1:]

	port16, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("port %q: %w", portHex, err)
	}

	var addr netip.Addr
	if ipv6 {
		if len(addrHex) != 32 {
			return netip.AddrPort{}, fmt.Errorf("ipv6 addr len %d, want 32", len(addrHex))
		}
		b, err := hex.DecodeString(addrHex)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("ipv6 hex: %w", err)
		}
		// Kernel stores each 32-bit word in host byte order (LE on x86).
		// Reverse each 4-byte group to recover network byte order.
		var raw [16]byte
		for i := 0; i < 4; i++ {
			raw[i*4+0] = b[i*4+3]
			raw[i*4+1] = b[i*4+2]
			raw[i*4+2] = b[i*4+1]
			raw[i*4+3] = b[i*4+0]
		}
		// Unmap IPv4-in-IPv6 (::ffff:x.x.x.x) so loopback/private checks work.
		addr = netip.AddrFrom16(raw).Unmap()
	} else {
		if len(addrHex) != 8 {
			return netip.AddrPort{}, fmt.Errorf("ipv4 addr len %d, want 8", len(addrHex))
		}
		v, err := strconv.ParseUint(addrHex, 16, 32)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("ipv4 hex: %w", err)
		}
		// v is the LE representation; write it as LE bytes to get NBO octets.
		var raw [4]byte
		binary.LittleEndian.PutUint32(raw[:], uint32(v))
		addr = netip.AddrFrom4(raw)
	}

	return netip.AddrPortFrom(addr, uint16(port16)), nil
}

// resolveInode returns (pid, exePath, cgroupContent) for the socket inode
// using the injected resolver or by scanning /proc/<pid>/fd/.
func (sc *Scanner) resolveInode(inode uint64) (pid int, exePath string, cgroupContent string) {
	if sc.src.InodeResolver != nil {
		return sc.src.InodeResolver(inode)
	}
	return sc.findSocket(inode)
}

// findSocket scans /proc/<pid>/fd/ symlinks for "socket:[inode]" to find
// which process owns the socket, then reads its exe path and cgroup.
func (sc *Scanner) findSocket(inode uint64) (pid int, exePath string, cgroupContent string) {
	target := fmt.Sprintf("socket:[%d]", inode)
	entries, err := os.ReadDir(sc.src.ProcDir) //nolint:gosec // ProcDir is /proc, admin-controlled
	if err != nil {
		return 0, "", ""
	}
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n <= 0 {
			continue
		}
		fdDir := filepath.Join(sc.src.ProcDir, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir) //nolint:gosec // path under /proc, admin-controlled
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name())) //nolint:gosec
			if err != nil {
				continue
			}
			if link != target {
				continue
			}
			exe, _ := os.Readlink(filepath.Join(sc.src.ProcDir, e.Name(), "exe"))            //nolint:gosec
			cgroupBytes, _ := os.ReadFile(filepath.Join(sc.src.ProcDir, e.Name(), "cgroup")) //nolint:gosec
			return n, exe, string(cgroupBytes)
		}
	}
	return 0, "", ""
}

// buildUserCache reads /etc/passwd once and returns uid→name. Returns nil
// when UserLookup is injected.
func (sc *Scanner) buildUserCache() map[uint32]string {
	if sc.src.UserLookup != nil {
		return nil
	}
	m := map[uint32]string{}
	f, err := os.Open(sc.src.PasswdPath) //nolint:gosec // path is /etc/passwd, admin-controlled
	if err != nil {
		return m
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.SplitN(s.Text(), ":", 7)
		if len(parts) < 3 {
			continue
		}
		uid, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			continue
		}
		m[uint32(uid)] = parts[0]
	}
	return m
}

func (sc *Scanner) resolveUser(uid uint32, cache map[uint32]string) string {
	if sc.src.UserLookup != nil {
		return sc.src.UserLookup(uid)
	}
	if name, ok := cache[uid]; ok {
		return name
	}
	return strconv.FormatUint(uint64(uid), 10)
}

// ParseCgroupOwner extracts ownerType, unitName, and containerID from the
// raw content of /proc/<pid>/cgroup. Exported for unit tests.
//
// Detects:
//   - cgroups-v2 docker scope:  /system.slice/docker-<ID>.scope
//   - cgroups-v1 docker path:   /docker/<ID>
//   - systemd service path:     *.service
func ParseCgroupOwner(content string) (ownerType, unitName, containerID string) {
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		cpath := parts[2]

		// Docker cgroups-v2: /system.slice/docker-<FULL_SHA>.scope
		if idx := strings.Index(cpath, "docker-"); idx >= 0 {
			rest := cpath[idx+7:]
			if end := strings.Index(rest, ".scope"); end >= 0 {
				return "docker", "", rest[:end]
			}
		}
		// Docker cgroups-v1: /docker/<SHA>
		if idx := strings.Index(cpath, "/docker/"); idx >= 0 {
			rest := cpath[idx+8:]
			if id := strings.SplitN(rest, "/", 2)[0]; len(id) > 0 {
				return "docker", "", id
			}
		}
		// Systemd service
		if strings.Contains(cpath, ".service") {
			return "systemd", filepath.Base(cpath), ""
		}
	}
	return "unknown", "", ""
}

// resolveLogSource determines the log source for l and populates
// ContainerName / ContainerImage as a side effect when InspectContainer is set.
func (sc *Scanner) resolveLogSource(ctx context.Context, l *Listener) string {
	switch l.OwnerType {
	case "systemd":
		if l.UnitName != "" {
			return "journald://" + l.UnitName
		}

	case "docker":
		if sc.src.InspectContainer != nil && l.ContainerID != "" {
			info, err := sc.src.InspectContainer(ctx, l.ContainerID)
			if err != nil {
				slog.WarnContext(ctx, "scan: docker inspect failed",
					"container", l.ContainerID, "err", err)
			} else {
				l.ContainerName = info.Name
				l.ContainerImage = info.Image
				// When the container name is known, return "docker:<name>" which
				// matches the DockerCollector source format and signals to the user
				// that "kind: docker" with "container: <name>" is the right config.
				if info.Name != "" {
					return "docker:" + info.Name
				}
				switch info.LogDriver {
				case "json-file":
					lp := info.LogPath
					if lp == "" {
						lp = fmt.Sprintf("/var/lib/docker/containers/%s/%s-json.log",
							l.ContainerID, l.ContainerID)
					}
					return lp
				case "journald":
					if info.UnitName != "" {
						return "journald://" + info.UnitName
					}
				}
			}
		}
	}

	// Public listener with no resolvable log source must never be silent.
	if l.IsPublic {
		return "⚠ no logs"
	}
	return ""
}

// ClassifyPublic returns true when the bind address is reachable from outside
// the host — i.e. it is not loopback and not a private/ULA range.
// 0.0.0.0 and :: (bind-all) are classified as public because they accept
// connections on every interface, including any public-facing one.
// Exported for unit tests.
func ClassifyPublic(addr netip.Addr) bool {
	if addr.IsLoopback() {
		return false
	}
	for _, p := range privateRanges {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// privateRanges covers RFC 1918, RFC 4193 (ULA), and RFC 3927 / RFC 4291
// link-local ranges that are never reachable from the public internet.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"), // IPv4 link-local
	netip.MustParsePrefix("fc00::/7"),       // IPv6 ULA
	netip.MustParsePrefix("fe80::/10"),      // IPv6 link-local
}
