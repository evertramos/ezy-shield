package scan_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/scan"
)

// fixtureReader opens a fixture file relative to the repository fixtures/scan/
// directory and returns its contents as an io.Reader.
func fixtureReader(t *testing.T, name string) *strings.Reader {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/scan/scan_test.go → ../../fixtures/scan/<name>
	path := filepath.Join(filepath.Dir(file), "..", "..", "fixtures", "scan", name)
	b, err := os.ReadFile(path) //nolint:gosec // path derived from runtime.Caller, not user input
	if err != nil {
		t.Fatalf("open fixture %s: %v", name, err)
	}
	return strings.NewReader(string(b))
}

// testInodeResolver maps known fixture inodes to synthetic /proc metadata.
func testInodeResolver(inode uint64) (pid int, exe string, cgroup string) {
	switch inode {
	case 14289: // 127.0.0.1:53 — systemd-resolved
		return 100, "/usr/sbin/systemd-resolved",
			"0::/system.slice/systemd-resolved.service\n"
	case 18432: // 0.0.0.0:80 — docker container
		return 200, "/usr/bin/containerd-shim",
			"0::/system.slice/docker-abc123def456abc123def456abc123def456abc123def456abc123def456abc12.scope\n"
	case 19000: // 0.0.0.0:22 — sshd (systemd)
		return 300, "/usr/sbin/sshd",
			"0::/system.slice/ssh.service\n"
	case 20000: // 127.0.0.1:5432 — postgres (systemd)
		return 400, "/usr/bin/postgres",
			"0::/system.slice/postgresql.service\n"
	case 21000: // [::]:22 — sshd IPv6 (same unit)
		return 300, "/usr/sbin/sshd",
			"0::/system.slice/ssh.service\n"
	}
	return 0, "", ""
}

func testUserLookup(uid uint32) string {
	switch uid {
	case 0:
		return "root"
	case 26:
		return "postgres"
	case 101:
		return "systemd-resolve"
	}
	return "unknown"
}

func TestScan_WithFixtures(t *testing.T) {
	sc := scan.New(scan.Sources{
		NetTCPReader:  fixtureReader(t, "proc_net_tcp.txt"),
		NetTCP6Reader: fixtureReader(t, "proc_net_tcp6.txt"),
		InodeResolver: testInodeResolver,
		UserLookup:    testUserLookup,
	})

	listeners, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// tcp fixture has 5 rows: 4 LISTEN + 1 ESTABLISHED (filtered).
	// tcp6 fixture has 1 LISTEN.
	if len(listeners) != 5 {
		t.Fatalf("want 5 listeners, got %d", len(listeners))
	}

	byAddr := make(map[string]scan.Listener, len(listeners))
	for _, l := range listeners {
		byAddr[l.Addr.String()] = l
	}

	cases := []struct {
		addr          string
		wantProto     string
		wantPublic    bool
		wantOwner     string
		wantUnit      string
		wantLogSource string
		wantUser      string
		wantPID       int
	}{
		{
			addr:          "127.0.0.1:53",
			wantProto:     "tcp",
			wantPublic:    false,
			wantOwner:     "systemd",
			wantUnit:      "systemd-resolved.service",
			wantLogSource: "journald://systemd-resolved.service",
			wantUser:      "systemd-resolve",
			wantPID:       100,
		},
		{
			addr:          "0.0.0.0:80",
			wantProto:     "tcp",
			wantPublic:    true,
			wantOwner:     "docker",
			wantLogSource: "⚠ no logs", // no InspectContainer injected
			wantUser:      "root",
			wantPID:       200,
		},
		{
			addr:          "0.0.0.0:22",
			wantProto:     "tcp",
			wantPublic:    true,
			wantOwner:     "systemd",
			wantUnit:      "ssh.service",
			wantLogSource: "journald://ssh.service",
			wantUser:      "root",
			wantPID:       300,
		},
		{
			addr:          "127.0.0.1:5432",
			wantProto:     "tcp",
			wantPublic:    false,
			wantOwner:     "systemd",
			wantUnit:      "postgresql.service",
			wantLogSource: "journald://postgresql.service",
			wantUser:      "postgres",
			wantPID:       400,
		},
		{
			addr:          "[::]:22",
			wantProto:     "tcp6",
			wantPublic:    true,
			wantOwner:     "systemd",
			wantUnit:      "ssh.service",
			wantLogSource: "journald://ssh.service",
			wantUser:      "root",
			wantPID:       300,
		},
	}

	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			l, ok := byAddr[tc.addr]
			if !ok {
				t.Fatalf("listener %s not found in results", tc.addr)
			}
			if l.Protocol != tc.wantProto {
				t.Errorf("Protocol: want %s, got %s", tc.wantProto, l.Protocol)
			}
			if l.IsPublic != tc.wantPublic {
				t.Errorf("IsPublic: want %v, got %v", tc.wantPublic, l.IsPublic)
			}
			if l.OwnerType != tc.wantOwner {
				t.Errorf("OwnerType: want %s, got %s", tc.wantOwner, l.OwnerType)
			}
			if tc.wantUnit != "" && l.UnitName != tc.wantUnit {
				t.Errorf("UnitName: want %s, got %s", tc.wantUnit, l.UnitName)
			}
			if l.LogSource != tc.wantLogSource {
				t.Errorf("LogSource: want %q, got %q", tc.wantLogSource, l.LogSource)
			}
			if l.UserName != tc.wantUser {
				t.Errorf("UserName: want %s, got %s", tc.wantUser, l.UserName)
			}
			if l.PID != tc.wantPID {
				t.Errorf("PID: want %d, got %d", tc.wantPID, l.PID)
			}
		})
	}
}

func TestScan_DockerInspect(t *testing.T) {
	inspectCalled := false
	sc := scan.New(scan.Sources{
		NetTCPReader:  fixtureReader(t, "proc_net_tcp.txt"),
		NetTCP6Reader: strings.NewReader("  sl  local_address remote_address st\n"),
		InodeResolver: testInodeResolver,
		UserLookup:    testUserLookup,
		InspectContainer: func(_ context.Context, id string) (*scan.ContainerInfo, error) {
			inspectCalled = true
			if !strings.HasPrefix(id, "abc123") {
				return nil, fmt.Errorf("unexpected container id: %s", id)
			}
			return &scan.ContainerInfo{
				Name:      "my-nginx",
				Image:     "nginx:latest",
				LogDriver: "json-file",
				LogPath:   "/var/lib/docker/containers/" + id + "/" + id + "-json.log",
			}, nil
		},
	})

	listeners, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !inspectCalled {
		t.Error("InspectContainer was never called")
	}

	var http scan.Listener
	for _, l := range listeners {
		if l.Addr.Port() == 80 {
			http = l
			break
		}
	}
	if http.ContainerName != "my-nginx" {
		t.Errorf("ContainerName: want my-nginx, got %s", http.ContainerName)
	}
	// LogSource now uses "docker:<name>" format to hint the kind: docker config.
	if http.LogSource != "docker:my-nginx" {
		t.Errorf("LogSource: want docker:my-nginx, got %s", http.LogSource)
	}
}

func TestClassifyPublic(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", false},
		{"::1", false},
		{"0.0.0.0", true},
		{"::", true},
		{"8.8.8.8", true},
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"172.32.0.1", true}, // outside 172.16/12
		{"192.168.1.1", false},
		{"198.51.100.213", true}, // outside 192.168/16
		{"169.254.1.1", false},   // link-local
		{"fc00::1", false},       // ULA
		{"fe80::1", false},       // link-local IPv6
		{"2001:db8::1", true},    // documentation range, but not RFC 1918
	}
	for _, tt := range tests {
		addr := netip.MustParseAddr(tt.addr)
		got := scan.ClassifyPublic(addr)
		if got != tt.want {
			t.Errorf("ClassifyPublic(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestParseCgroupOwner(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantType string
		wantUnit string
		wantCID  string
	}{
		{
			name:     "systemd service cgroup-v2",
			content:  "0::/system.slice/nginx.service\n",
			wantType: "systemd",
			wantUnit: "nginx.service",
		},
		{
			name:     "systemd service cgroup-v1",
			content:  "1:name=systemd:/system.slice/ssh.service\n12:devices:/system.slice/ssh.service\n",
			wantType: "systemd",
			wantUnit: "ssh.service",
		},
		{
			name:     "docker cgroup-v2 scope",
			content:  "0::/system.slice/docker-abc123def456.scope\n",
			wantType: "docker",
			wantCID:  "abc123def456",
		},
		{
			name:     "docker cgroup-v1 path",
			content:  "1:name=systemd:/docker/abc123def456abc123def456\n",
			wantType: "docker",
			wantCID:  "abc123def456abc123def456",
		},
		{
			name:     "unknown user slice",
			content:  "0::/user.slice/user-1000.slice/session-5.scope\n",
			wantType: "unknown",
		},
		{
			name:     "empty",
			content:  "",
			wantType: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ot, unit, cid := scan.ParseCgroupOwner(tt.content)
			if ot != tt.wantType {
				t.Errorf("type: want %q, got %q", tt.wantType, ot)
			}
			if unit != tt.wantUnit {
				t.Errorf("unit: want %q, got %q", tt.wantUnit, unit)
			}
			if cid != tt.wantCID {
				t.Errorf("cid: want %q, got %q", tt.wantCID, cid)
			}
		})
	}
}

func TestParseHexAddrPort_IPv4(t *testing.T) {
	// Use the fixture content to implicitly test this via Scan, and explicitly
	// test edge cases with inline readers.
	tests := []struct {
		input    string
		wantIP   string
		wantPort uint16
	}{
		{"0100007F:0035", "127.0.0.1", 53},
		{"00000000:0050", "0.0.0.0", 80},
		{"00000000:0016", "0.0.0.0", 22},
		{"0100007F:1538", "127.0.0.1", 5432},
	}
	for _, tt := range tests {
		line := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			"   0: " + tt.input + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000\n"
		sc := scan.New(scan.Sources{
			NetTCPReader:  strings.NewReader(line),
			NetTCP6Reader: strings.NewReader("  sl\n"),
			InodeResolver: func(uint64) (int, string, string) { return 0, "", "" },
			UserLookup:    func(uint32) string { return "root" },
		})
		ls, err := sc.Scan(context.Background())
		if err != nil {
			t.Errorf("Scan(%s): %v", tt.input, err)
			continue
		}
		if len(ls) != 1 {
			t.Errorf("Scan(%s): want 1 listener, got %d", tt.input, len(ls))
			continue
		}
		if ls[0].Addr.Addr().String() != tt.wantIP {
			t.Errorf("Scan(%s) IP: want %s, got %s", tt.input, tt.wantIP, ls[0].Addr.Addr())
		}
		if ls[0].Addr.Port() != tt.wantPort {
			t.Errorf("Scan(%s) Port: want %d, got %d", tt.input, tt.wantPort, ls[0].Addr.Port())
		}
	}
}

func TestScan_NoLog_PublicUnknown(t *testing.T) {
	// A public listener with OwnerType "unknown" (no PID) must emit "⚠ no logs".
	line := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:270F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55555 1\n"
	sc := scan.New(scan.Sources{
		NetTCPReader:  strings.NewReader(line),
		NetTCP6Reader: strings.NewReader("  sl\n"),
		InodeResolver: func(uint64) (int, string, string) { return 0, "", "" },
		UserLookup:    func(uint32) string { return "root" },
	})
	ls, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(ls) != 1 {
		t.Fatalf("want 1 listener, got %d", len(ls))
	}
	l := ls[0]
	if !l.IsPublic {
		t.Error("want IsPublic=true for 0.0.0.0:9999")
	}
	if l.LogSource != "⚠ no logs" {
		t.Errorf("LogSource: want ⚠ no logs, got %q", l.LogSource)
	}
}
