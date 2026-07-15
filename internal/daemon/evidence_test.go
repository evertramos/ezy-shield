package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// writeLog writes a temp log file and returns its path.
func writeLog(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write log fixture: %v", err)
	}
	return path
}

// fileCollectorCfg returns a config with a single file log source.
func fileCollectorCfg(path string) *config.Config {
	return &config.Config{Collectors: []config.CollectorCfg{{Kind: "file", Path: path}}}
}

func TestCollectEvidence_FileSource(t *testing.T) {
	d, _ := newReportTestDaemon(t)
	log := "" +
		"203.0.113.7 - - [15/Jan/2026:10:00:01 +0000] \"GET /wp-login.php HTTP/1.1\" 404 0\n" +
		"198.51.100.9 - - [15/Jan/2026:10:00:02 +0000] \"GET / HTTP/1.1\" 200 5\n" +
		"1203.0.113.7 - - near miss prefix\n" +
		"203.0.113.71 - - near miss suffix\n" +
		"connect from 203.0.113.7:44321 upstream\n" +
		"203.0.113.7 - - [15/Jan/2026:10:00:09 +0000] \"GET /.env HTTP/1.1\" 404 0\n"
	d.cfg = fileCollectorCfg(writeLog(t, "access.log", log))

	evs := d.collectEvidence(context.Background(), netip.MustParseAddr("203.0.113.7"))
	if len(evs) != 1 {
		t.Fatalf("want 1 evidence entry, got %d: %+v", len(evs), evs)
	}
	ev := evs[0]
	if !strings.HasPrefix(ev.Source, "file:") {
		t.Errorf("source: want file: prefix, got %q", ev.Source)
	}
	if len(ev.Lines) != 3 {
		t.Fatalf("want 3 matching lines (exact-token only), got %d: %q", len(ev.Lines), ev.Lines)
	}
	if !strings.Contains(ev.Lines[1], "203.0.113.7:44321") {
		t.Errorf("port-suffixed match missing: %q", ev.Lines)
	}
	if ev.Truncated || ev.Note != "" {
		t.Errorf("small clean log: want no truncation/note, got %+v", ev)
	}
}

func TestCollectEvidence_LineCapKeepsNewest(t *testing.T) {
	d, _ := newReportTestDaemon(t)
	var b strings.Builder
	for i := 0; i < evidenceMaxLines+10; i++ {
		fmt.Fprintf(&b, "203.0.113.7 - - request %d\n", i)
	}
	d.cfg = fileCollectorCfg(writeLog(t, "big.log", b.String()))

	evs := d.collectEvidence(context.Background(), netip.MustParseAddr("203.0.113.7"))
	ev := evs[0]
	if len(ev.Lines) != evidenceMaxLines {
		t.Fatalf("want %d lines, got %d", evidenceMaxLines, len(ev.Lines))
	}
	if !ev.Truncated {
		t.Error("cap applied: Truncated must be true")
	}
	// Most recent matches survive: the last line of the file is present,
	// the first is not.
	last := fmt.Sprintf("request %d", evidenceMaxLines+9)
	if !strings.Contains(ev.Lines[len(ev.Lines)-1], last) {
		t.Errorf("want newest line %q kept, got tail %q", last, ev.Lines[len(ev.Lines)-1])
	}
	if strings.Contains(ev.Lines[0], "request 0\n") {
		t.Errorf("oldest line must be dropped, got head %q", ev.Lines[0])
	}
}

func TestCollectEvidence_LongLineTruncated(t *testing.T) {
	d, _ := newReportTestDaemon(t)
	long := "203.0.113.7 " + strings.Repeat("A", 3*evidenceMaxLineBytes) + "\n"
	d.cfg = fileCollectorCfg(writeLog(t, "long.log", long))

	evs := d.collectEvidence(context.Background(), netip.MustParseAddr("203.0.113.7"))
	ev := evs[0]
	if len(ev.Lines) != 1 {
		t.Fatalf("want 1 line, got %d", len(ev.Lines))
	}
	if len(ev.Lines[0]) != evidenceMaxLineBytes {
		t.Errorf("line length: want %d, got %d", evidenceMaxLineBytes, len(ev.Lines[0]))
	}
	if !ev.Truncated {
		t.Error("oversized line: Truncated must be true")
	}
}

func TestCollectEvidence_Degradation(t *testing.T) {
	d, _ := newReportTestDaemon(t)
	okLog := writeLog(t, "ok.log", "no such address here\n")
	d.cfg = &config.Config{Collectors: []config.CollectorCfg{
		{Kind: "file", Path: okLog},
		{Kind: "file", Path: filepath.Join(t.TempDir(), "rotated.log")}, // absent
		{Kind: "journald", Unit: "sshd"},
		{Kind: "docker", Container: "web"},
	}}
	// Controlled fakes: never touch the host's journalctl or docker socket.
	d.evidenceJournalctl = writeFakeJournalctl(t, "sshd", "") // emits nothing
	d.evidenceDockerSocket = filepath.Join(t.TempDir(), "no-such.sock")

	evs := d.collectEvidence(context.Background(), netip.MustParseAddr("203.0.113.7"))
	if len(evs) != 4 {
		t.Fatalf("want 4 evidence entries, got %d: %+v", len(evs), evs)
	}
	if evs[0].Note == "" || len(evs[0].Lines) != 0 {
		t.Errorf("no-match source must carry a note and no lines: %+v", evs[0])
	}
	if !strings.Contains(evs[1].Note, "not readable") {
		t.Errorf("missing file: want honest note, got %+v", evs[1])
	}
	if evs[2].Source != "journald:sshd" || !strings.Contains(evs[2].Note, "no entries mentioning") {
		t.Errorf("journald: want empty-journal note, got %+v", evs[2])
	}
	if evs[3].Source != "docker:web" || !strings.Contains(evs[3].Note, "socket unreachable") {
		t.Errorf("docker: want unreachable-socket note, got %+v", evs[3])
	}
}

func TestCollectEvidence_NoSourcesConfigured(t *testing.T) {
	d, _ := newReportTestDaemon(t) // d.cfg is nil

	evs := d.collectEvidence(context.Background(), netip.MustParseAddr("203.0.113.7"))
	if len(evs) != 1 || evs[0].Note != "no log sources configured" {
		t.Errorf("want single explanatory entry, got %+v", evs)
	}
}

// TestHandleReport_Evidence exercises the full socket path: evidence only
// appears when requested.
func TestHandleReport_Evidence(t *testing.T) {
	d, db := newReportTestDaemon(t)
	ip := netip.MustParseAddr("203.0.113.7")
	seedStrike(t, db, ip, 1, time.Hour, "ssh brute force")
	d.cfg = fileCollectorCfg(writeLog(t, "auth.log",
		"Failed password for root from 203.0.113.7 port 51544 ssh2\n"))

	decode := func(t *testing.T, resp SocketResponse) sdk.AbuseReport {
		t.Helper()
		if !resp.OK {
			t.Fatalf("report failed: %s", resp.Error)
		}
		var rep sdk.AbuseReport
		if err := json.Unmarshal(resp.Data, &rep); err != nil {
			t.Fatalf("unmarshal report: %v", err)
		}
		return rep
	}

	with := decode(t, callSocket(t, d, SocketRequest{Verb: "report", IP: ip.String(), Evidence: true}))
	if len(with.Evidence) != 1 || len(with.Evidence[0].Lines) != 1 {
		t.Fatalf("want evidence with 1 line, got %+v", with.Evidence)
	}
	if !strings.Contains(with.Evidence[0].Lines[0], "Failed password") {
		t.Errorf("evidence line mismatch: %q", with.Evidence[0].Lines[0])
	}

	without := decode(t, callSocket(t, d, SocketRequest{Verb: "report", IP: ip.String()}))
	if without.Evidence != nil {
		t.Errorf("evidence must be absent when not requested, got %+v", without.Evidence)
	}
}

func TestContainsIPToken(t *testing.T) {
	tests := []struct {
		name string
		line string
		ip   string
		isV4 bool
		want bool
	}{
		{"plain v4", "GET from 1.2.3.4 done", "1.2.3.4", true, true},
		{"start of line", "1.2.3.4 - - GET /", "1.2.3.4", true, true},
		{"end of line", "peer 1.2.3.4", "1.2.3.4", true, true},
		{"v4 with port", "connect 1.2.3.4:443", "1.2.3.4", true, true},
		{"prefix digit", "11.2.3.4 - -", "1.2.3.4", true, false},
		{"suffix digit", "1.2.3.45 - -", "1.2.3.4", true, false},
		{"suffix octet", "1.2.3.4.5 - -", "1.2.3.4", true, false},
		{"second occurrence valid", "11.2.3.4 then 1.2.3.4 ok", "1.2.3.4", true, true},
		{"absent", "5.6.7.8 - -", "1.2.3.4", true, false},
		{"plain v6", "from 2001:db8::1 port 22", "2001:db8::1", false, true},
		{"v6 hex suffix", "from 2001:db8::1a port 22", "2001:db8::1", false, false},
		{"v6 digit suffix", "from 2001:db8::12 port 22", "2001:db8::1", false, false},
		{"v6 colon suffix", "from 2001:db8::1:2 port 22", "2001:db8::1", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := containsIPToken([]byte(tc.line), tc.ip, tc.isV4)
			if got != tc.want {
				t.Errorf("containsIPToken(%q, %q) = %v, want %v", tc.line, tc.ip, got, tc.want)
			}
		})
	}
}
