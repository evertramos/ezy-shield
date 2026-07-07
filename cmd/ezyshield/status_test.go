package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// mockDaemonServer starts a unix socket server that handles one connection
// and serves a fixed status + list response.
func mockDaemonServer(t *testing.T, dir string, statusResp daemon.SocketResponse, listResp daemon.SocketResponse) string {
	t.Helper()
	sockPath := filepath.Join(dir, "daemon.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})

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
				switch req.Verb {
				case "status":
					_ = json.NewEncoder(c).Encode(statusResp)
				case "list":
					_ = json.NewEncoder(c).Encode(listResp)
				}
			}(conn)
		}
	}()

	return sockPath
}

// mockEnforcerServer starts a unix socket server that only accepts connections
// (no protocol — the probe just tests reachability).
func mockEnforcerServer(t *testing.T, dir string) string {
	t.Helper()
	sockPath := filepath.Join(dir, "enforcer.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	return sockPath
}

func makeStatusResp(sd daemon.StatusData) daemon.SocketResponse {
	raw, _ := json.Marshal(sd)
	return daemon.SocketResponse{OK: true, Data: json.RawMessage(raw)}
}

func makeListResp(entries []daemon.BanEntry) daemon.SocketResponse {
	raw, _ := json.Marshal(entries)
	return daemon.SocketResponse{OK: true, Data: json.RawMessage(raw)}
}

func runStatusCmd(t *testing.T, daemonSock, enforcerSock string) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := newStatusCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	// inject socket paths via flags
	root := &cobra.Command{Use: "ezyshield"}
	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "")
	root.AddCommand(cmd)
	jsonOutput = false
	root.SetArgs([]string{
		"status",
		"--socket", daemonSock,
		"--enforcer-socket", enforcerSock,
	})
	_ = root.Execute()
	return stdout.String(), stderr.String()
}

func runStatusCmdJSON(t *testing.T, daemonSock, enforcerSock string) StatusOutput {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := newStatusCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	root := &cobra.Command{Use: "ezyshield"}
	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "")
	root.AddCommand(cmd)
	jsonOutput = true
	root.SetArgs([]string{
		"status",
		"--socket", daemonSock,
		"--enforcer-socket", enforcerSock,
	})
	_ = root.Execute()
	jsonOutput = false

	var out StatusOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("parse json output: %v\nraw: %s", err, stdout.String())
	}
	return out
}

func TestStatus_DaemonRunning_EnforcerRunning(t *testing.T) {
	dir := t.TempDir()
	sd := daemon.StatusData{
		Uptime:     "2h3m",
		Armed:      true,
		ActiveBans: 5,
		Version:    "v0.9.0",
	}
	entries := []daemon.BanEntry{
		{IP: "1.1.1.1", Strike: 1, TTL: "5m"},
		{IP: "2.2.2.2", Strike: 1, TTL: "1h"},
		{IP: "3.3.3.3", Strike: 2, TTL: "24h"},
		{IP: "4.4.4.4", Strike: 0, TTL: "permanent"},
		{IP: "5.5.5.5", Strike: 3, TTL: "permanent"},
	}
	daemonSock := mockDaemonServer(t, dir, makeStatusResp(sd), makeListResp(entries))
	enforcerSock := mockEnforcerServer(t, dir)

	out, _ := runStatusCmd(t, daemonSock, enforcerSock)
	if !strings.Contains(out, "daemon:    running") {
		t.Errorf("expected daemon running, got: %s", out)
	}
	if !strings.Contains(out, "enforcer:  running") {
		t.Errorf("expected enforcer running, got: %s", out)
	}
	if !strings.Contains(out, "mode:      enforce") {
		t.Errorf("expected enforce mode, got: %s", out)
	}
	if !strings.Contains(out, "uptime:    2h3m") {
		t.Errorf("expected uptime, got: %s", out)
	}
	if !strings.Contains(out, "version:   v0.9.0") {
		t.Errorf("expected version, got: %s", out)
	}
	if !strings.Contains(out, "bans:      5") {
		t.Errorf("expected bans count, got: %s", out)
	}
	// strike 3 with ttl "permanent" → "permanent" bucket
	if !strings.Contains(out, "permanent:") {
		t.Errorf("expected permanent bucket in output, got: %s", out)
	}
	if !strings.Contains(out, "strike 1:") {
		t.Errorf("expected strike 1 bucket in output, got: %s", out)
	}
	if !strings.Contains(out, "strike 2:") {
		t.Errorf("expected strike 2 bucket in output, got: %s", out)
	}
}

func TestStatus_DaemonStopped(t *testing.T) {
	dir := t.TempDir()
	daemonSock := filepath.Join(dir, "no-daemon.sock") // intentionally absent
	enforcerSock := filepath.Join(dir, "no-enforcer.sock")

	out, _ := runStatusCmd(t, daemonSock, enforcerSock)
	if !strings.Contains(out, "daemon:    stopped") {
		t.Errorf("expected daemon stopped, got: %s", out)
	}
	if !strings.Contains(out, "enforcer:  stopped") {
		t.Errorf("expected enforcer stopped, got: %s", out)
	}
}

func TestStatus_EnforcerStopped_DaemonRunning(t *testing.T) {
	dir := t.TempDir()
	sd := daemon.StatusData{Uptime: "1m", Armed: false, ActiveBans: 0, Version: "v0.1.0"}
	daemonSock := mockDaemonServer(t, dir, makeStatusResp(sd), makeListResp(nil))
	enforcerSock := filepath.Join(dir, "no-enforcer.sock") // intentionally absent

	out, _ := runStatusCmd(t, daemonSock, enforcerSock)
	if !strings.Contains(out, "daemon:    running") {
		t.Errorf("expected daemon running, got: %s", out)
	}
	if !strings.Contains(out, "enforcer:  stopped") {
		t.Errorf("expected enforcer stopped, got: %s", out)
	}
}

func TestStatus_DryRunMode(t *testing.T) {
	dir := t.TempDir()
	sd := daemon.StatusData{Uptime: "5m", Armed: false, ActiveBans: 0, Version: "v0.1.0"}
	daemonSock := mockDaemonServer(t, dir, makeStatusResp(sd), makeListResp(nil))
	enforcerSock := mockEnforcerServer(t, dir)

	out, _ := runStatusCmd(t, daemonSock, enforcerSock)
	if !strings.Contains(out, "mode:      dry-run") {
		t.Errorf("expected dry-run mode, got: %s", out)
	}
}

func TestStatus_NoBans(t *testing.T) {
	dir := t.TempDir()
	sd := daemon.StatusData{Uptime: "10m", Armed: true, ActiveBans: 0, Version: "v1.0.0"}
	daemonSock := mockDaemonServer(t, dir, makeStatusResp(sd), makeListResp(nil))
	enforcerSock := mockEnforcerServer(t, dir)

	out, _ := runStatusCmd(t, daemonSock, enforcerSock)
	if !strings.Contains(out, "bans:      0") {
		t.Errorf("expected bans 0, got: %s", out)
	}
	if strings.Contains(out, "by strike") {
		t.Errorf("expected no by-strike section when no bans, got: %s", out)
	}
}

func TestStatus_JSONOutput_Full(t *testing.T) {
	dir := t.TempDir()
	sd := daemon.StatusData{
		Uptime:     "1h",
		Armed:      true,
		ActiveBans: 3,
		Version:    "v1.0.0",
	}
	entries := []daemon.BanEntry{
		{IP: "10.0.0.1", Strike: 1, TTL: "5m"},
		{IP: "10.0.0.2", Strike: 2, TTL: "24h"},
		{IP: "10.0.0.3", Strike: 0, TTL: "permanent"},
	}
	daemonSock := mockDaemonServer(t, dir, makeStatusResp(sd), makeListResp(entries))
	enforcerSock := mockEnforcerServer(t, dir)

	out := runStatusCmdJSON(t, daemonSock, enforcerSock)
	if out.Daemon != "running" {
		t.Errorf("daemon = %q, want running", out.Daemon)
	}
	if out.Enforcer != "running" {
		t.Errorf("enforcer = %q, want running", out.Enforcer)
	}
	if out.Mode != "enforce" {
		t.Errorf("mode = %q, want enforce", out.Mode)
	}
	if out.ActiveBans != 3 {
		t.Errorf("active_bans = %d, want 3", out.ActiveBans)
	}
	if out.BansByStrike["strike 1"] != 1 {
		t.Errorf("bans_by_strike[strike 1] = %d, want 1", out.BansByStrike["strike 1"])
	}
	if out.BansByStrike["strike 2"] != 1 {
		t.Errorf("bans_by_strike[strike 2] = %d, want 1", out.BansByStrike["strike 2"])
	}
	if out.BansByStrike["permanent"] != 1 {
		t.Errorf("bans_by_strike[permanent] = %d, want 1", out.BansByStrike["permanent"])
	}
}

func TestStatus_JSONOutput_DaemonStopped(t *testing.T) {
	dir := t.TempDir()
	daemonSock := filepath.Join(dir, "no-daemon.sock")
	enforcerSock := filepath.Join(dir, "no-enforcer.sock")

	out := runStatusCmdJSON(t, daemonSock, enforcerSock)
	if out.Daemon != "stopped" {
		t.Errorf("daemon = %q, want stopped", out.Daemon)
	}
	if out.Enforcer != "stopped" {
		t.Errorf("enforcer = %q, want stopped", out.Enforcer)
	}
}

func TestStrikeKey(t *testing.T) {
	cases := []struct {
		strike int
		ttl    string
		want   string
	}{
		{1, "5m", "strike 1"},
		{2, "24h", "strike 2"},
		{3, "7d", "strike 3"},
		{0, "permanent", "permanent"},
		{5, "permanent", "permanent"},
		{1, "permanent", "permanent"},
	}
	for _, tc := range cases {
		got := strikeKey(tc.strike, tc.ttl)
		if got != tc.want {
			t.Errorf("strikeKey(%d, %q) = %q, want %q", tc.strike, tc.ttl, got, tc.want)
		}
	}
}
