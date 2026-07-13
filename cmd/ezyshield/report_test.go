package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// mockReportServer serves the "report" verb from a unix socket and records
// every request it sees so tests can assert the wire shape.
func mockReportServer(t *testing.T, resp daemon.SocketResponse) (sockPath string, gotReqs *[]daemon.SocketRequest) {
	t.Helper()
	dir := t.TempDir()
	sockPath = filepath.Join(dir, "daemon.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})

	reqs := &[]daemon.SocketRequest{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				var req daemon.SocketRequest
				if err := json.NewDecoder(c).Decode(&req); err != nil {
					return
				}
				*reqs = append(*reqs, req)
				_ = json.NewEncoder(c).Encode(resp)
			}(conn)
		}
	}()
	return sockPath, reqs
}

func dataResp(t *testing.T, v any) daemon.SocketResponse {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return daemon.SocketResponse{OK: true, Data: raw}
}

// runReportCmd executes the report command with args and returns stdout and
// the command error.
func runReportCmd(t *testing.T, jsonMode bool, args ...string) (string, error) {
	t.Helper()
	var stdout bytes.Buffer
	cmd := newReportCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	root := &cobra.Command{Use: "ezyshield"}
	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "")
	root.AddCommand(cmd)
	jsonOutput = jsonMode
	defer func() { jsonOutput = false }()
	root.SetOut(&stdout)
	root.SetErr(&stdout)
	root.SetArgs(append([]string{"report"}, args...))
	err := root.Execute()
	return stdout.String(), err
}

// fixtureReport returns a report with hostile bytes in log-derived fields.
func fixtureReport() sdk.AbuseReport {
	return sdk.AbuseReport{
		SchemaVersion: sdk.AbuseReportSchemaVersion,
		GeneratedAt:   "2026-07-13T12:00:00Z",
		IP:            "203.0.113.7",
		FirstSeen:     "2026-07-12T09:00:00Z",
		LastSeen:      "2026-07-13T11:00:00Z",
		TotalStrikes:  2,
		Country:       "NL",
		ASN:           "AS12345",
		ASNOrg:        "Example BV",
		CurrentBan: &sdk.AbuseReportBan{
			BannedAt:  "2026-07-13T11:00:00Z",
			ExpiresAt: "2026-07-13T12:00:00Z",
			Strike:    2,
			Reason:    "ssh brute force \x1b[31magain\x1b[0m",
		},
		Strikes: []sdk.AbuseReportStrike{
			{
				RecordedAt: "2026-07-13T11:00:00Z",
				Strike:     2,
				TTLSeconds: 3600,
				Reason:     "evil | user\r\nfrom log",
				Verdicts: []sdk.AbuseReportVerdict{
					{Score: 92, Category: "ssh_bruteforce", Confidence: 0.9, Reason: "5 failures", Source: "rules"},
				},
			},
			{
				RecordedAt: "2026-07-12T09:00:00Z",
				Strike:     1,
				TTLSeconds: 300,
				Reason:     "first strike",
			},
		},
		Actions: []sdk.AbuseReportAction{
			{RecordedAt: "2026-07-13T11:00:00Z", Op: "ban", TTLSeconds: 3600, Strike: 2, Reason: "escalated"},
			{RecordedAt: "2026-07-12T09:00:00Z", Op: "ban", TTLSeconds: 300, Strike: 1, Reason: "first strike"},
		},
	}
}

// fixtureReportWithEvidence extends fixtureReport with hostile evidence:
// ANSI escapes and a markdown fence-injection attempt.
func fixtureReportWithEvidence() sdk.AbuseReport {
	rep := fixtureReport()
	rep.Evidence = []sdk.AbuseReportEvidence{
		{
			Source: "file:/var/log/auth.log",
			Lines: []string{
				"Failed password for root from 203.0.113.7 port 51544 ssh2",
				"```\x1b[31m# Fake heading injected from log\x1b[0m",
			},
			Truncated: true,
		},
		{
			Source: "journald:sshd",
			Note:   "journald sources do not support on-demand extraction yet; use: journalctl -u sshd --grep 203.0.113.7",
		},
	}
	return rep
}

func TestReport_TextOutput(t *testing.T) {
	sock, reqs := mockReportServer(t, dataResp(t, fixtureReport()))

	out, err := runReportCmd(t, false, "203.0.113.7", "--socket", sock)
	if err != nil {
		t.Fatalf("report: %v\n%s", err, out)
	}

	for _, want := range []string{
		"Abuse report — 203.0.113.7",
		"total strikes: 2",
		"country:       NL",
		"network:       AS12345 (Example BV)",
		"Current ban",
		"strike:    2",
		"Strike history (newest first)",
		"[2] 2026-07-13T11:00:00Z  ttl 1h0m0s",
		"rules: ssh_bruteforce (score 92, confidence 0.90) — 5 failures",
		"Actions (newest first)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	// Hostile bytes from log-derived fields must never reach the terminal.
	if strings.ContainsRune(out, 0x1b) && colorEnabled(nil) {
		t.Error("unexpected ESC handling") // unreachable guard; see next check
	}
	if strings.Contains(out, "\x1b[31m") {
		t.Errorf("ANSI escape from hostile reason leaked into output:\n%q", out)
	}

	// Wire shape: single per-IP request, evidence not requested by default.
	if len(*reqs) != 1 || (*reqs)[0].Verb != "report" || (*reqs)[0].IP != "203.0.113.7" {
		t.Errorf("request: want one report req for the IP, got %+v", *reqs)
	}
	if (*reqs)[0].Evidence {
		t.Errorf("request: evidence must be false without --evidence, got %+v", (*reqs)[0])
	}
}

func TestReport_EvidenceText(t *testing.T) {
	sock, reqs := mockReportServer(t, dataResp(t, fixtureReportWithEvidence()))

	out, err := runReportCmd(t, false, "203.0.113.7", "--evidence", "--socket", sock)
	if err != nil {
		t.Fatalf("report --evidence: %v\n%s", err, out)
	}

	for _, want := range []string{
		"Evidence — file:/var/log/auth.log",
		"    Failed password for root from 203.0.113.7 port 51544 ssh2",
		"(excerpt truncated by size caps)",
		"Evidence — journald:sshd",
		"note: journald sources do not support on-demand extraction yet",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[31m") {
		t.Errorf("ANSI escape from hostile evidence line leaked:\n%q", out)
	}
	if len(*reqs) != 1 || !(*reqs)[0].Evidence {
		t.Errorf("request: want Evidence=true on the wire, got %+v", *reqs)
	}
}

func TestReport_EvidenceMarkdown(t *testing.T) {
	sock, _ := mockReportServer(t, dataResp(t, fixtureReportWithEvidence()))

	out, err := runReportCmd(t, false, "203.0.113.7", "--evidence", "-o", "md", "--socket", sock)
	if err != nil {
		t.Fatalf("report --evidence -o md: %v\n%s", err, out)
	}

	for _, want := range []string{
		"## Evidence (log excerpts)",
		"### file:/var/log/auth.log",
		"    Failed password for root from 203.0.113.7 port 51544 ssh2",
		"_(excerpt truncated by size caps)_",
		"### journald:sshd",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
	// Fence-injection attempt: the hostile ``` line must stay indented (part
	// of the code block) and never start a line at column 0.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "```") {
			t.Errorf("unindented fence leaked into markdown: %q", line)
		}
	}
	if !strings.Contains(out, "    ```") {
		t.Errorf("hostile fence line must be kept, indented as code:\n%s", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("ANSI escape leaked into markdown evidence:\n%q", out)
	}
}

func TestReport_JSONOutput(t *testing.T) {
	sock, _ := mockReportServer(t, dataResp(t, fixtureReport()))

	out, err := runReportCmd(t, true, "203.0.113.7", "--socket", sock)
	if err != nil {
		t.Fatalf("report --json: %v\n%s", err, out)
	}
	var rep sdk.AbuseReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("parse json output: %v\nraw: %s", err, out)
	}
	if rep.SchemaVersion != sdk.AbuseReportSchemaVersion {
		t.Errorf("schema_version: want %d, got %d", sdk.AbuseReportSchemaVersion, rep.SchemaVersion)
	}
	if rep.IP != "203.0.113.7" || len(rep.Strikes) != 2 {
		t.Errorf("json round-trip mismatch: %+v", rep)
	}
}

func TestReport_MarkdownOutput(t *testing.T) {
	sock, _ := mockReportServer(t, dataResp(t, fixtureReport()))

	out, err := runReportCmd(t, false, "203.0.113.7", "-o", "md", "--socket", sock)
	if err != nil {
		t.Fatalf("report -o md: %v\n%s", err, out)
	}

	for _, want := range []string{
		"# Abuse Report: 203.0.113.7",
		"- **Generated:** 2026-07-13T12:00:00Z",
		"- **Network:** AS12345 (Example BV)",
		"## Current ban",
		"## Incident history (newest first)",
		"## Actions taken (newest first)",
		"_Generated by [EzyShield](https://github.com/evertramos/ezy-shield)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}

	// Hostile reason: pipe escaped (table intact), CR/LF and ANSI stripped.
	if !strings.Contains(out, `evil \| userfrom log`) {
		t.Errorf("hostile reason not sanitized/escaped for the table:\n%s", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("ANSI escape leaked into markdown:\n%q", out)
	}
}

func TestReport_MarkdownNoFooter(t *testing.T) {
	sock, _ := mockReportServer(t, dataResp(t, fixtureReport()))

	out, err := runReportCmd(t, false, "203.0.113.7", "-o", "md", "--no-footer", "--socket", sock)
	if err != nil {
		t.Fatalf("report -o md --no-footer: %v\n%s", err, out)
	}
	if strings.Contains(out, "Generated by [EzyShield]") {
		t.Errorf("--no-footer must omit the footer:\n%s", out)
	}
}

func TestReport_ListMode(t *testing.T) {
	entries := []daemon.ReportSummaryEntry{
		{IP: "203.0.113.7", FirstSeen: "2026-07-12T09:00:00Z", LastSeen: "2026-07-13T11:00:00Z",
			TotalStrikes: 2, Banned: true, Country: "NL", ASN: "AS12345"},
		{IP: "198.51.100.9", FirstSeen: "2026-07-10T09:00:00Z", LastSeen: "2026-07-10T09:00:00Z",
			TotalStrikes: 5, Banned: true, Permanent: true},
	}
	sock, reqs := mockReportServer(t, dataResp(t, entries))

	out, err := runReportCmd(t, false, "--socket", sock)
	if err != nil {
		t.Fatalf("report list: %v\n%s", err, out)
	}
	for _, want := range []string{"IP", "STRIKES", "203.0.113.7", "198.51.100.9", "permanent", "yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("listing missing %q:\n%s", want, out)
		}
	}
	if len(*reqs) != 1 || (*reqs)[0].IP != "" || (*reqs)[0].Filter != "" {
		t.Errorf("request: want listing req without filter, got %+v", *reqs)
	}
}

func TestReport_ListPermanentFilter(t *testing.T) {
	sock, reqs := mockReportServer(t, dataResp(t, []daemon.ReportSummaryEntry{}))

	out, err := runReportCmd(t, false, "--permanent", "--socket", sock)
	if err != nil {
		t.Fatalf("report --permanent: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no permanently banned offenders") {
		t.Errorf("want empty-listing message, got:\n%s", out)
	}
	if len(*reqs) != 1 || (*reqs)[0].Filter != "permanent" {
		t.Errorf("request: want filter=permanent, got %+v", *reqs)
	}
}

func TestReport_ListJSON(t *testing.T) {
	entries := []daemon.ReportSummaryEntry{{IP: "203.0.113.7", TotalStrikes: 2, Banned: true}}
	sock, _ := mockReportServer(t, dataResp(t, entries))

	out, err := runReportCmd(t, true, "--socket", sock)
	if err != nil {
		t.Fatalf("report list --json: %v\n%s", err, out)
	}
	var got []daemon.ReportSummaryEntry
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("parse json output: %v\nraw: %s", err, out)
	}
	if len(got) != 1 || got[0].IP != "203.0.113.7" {
		t.Errorf("json listing mismatch: %+v", got)
	}
}

func TestReport_ArgValidation(t *testing.T) {
	tests := []struct {
		name string
		json bool
		args []string
	}{
		{"cidr rejected", false, []string{"203.0.113.0/24"}},
		{"garbage rejected", false, []string{"not-an-ip"}},
		{"ip with --permanent", false, []string{"203.0.113.7", "--permanent"}},
		{"md without ip", false, []string{"-o", "md"}},
		{"evidence without ip", false, []string{"--evidence"}},
		{"invalid output", false, []string{"203.0.113.7", "-o", "pdf"}},
		{"json with md", true, []string{"203.0.113.7", "-o", "md"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// No server needed: validation must fail before any dial.
			if _, err := runReportCmd(t, tc.json, tc.args...); err == nil {
				t.Errorf("want error for args %v, got nil", tc.args)
			}
		})
	}
}
