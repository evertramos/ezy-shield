package main

// Tests for the global exit-code convention (issue #106): 0 success,
// 1 runtime error, 2 usage error, 3 daemon unreachable. These drive the full
// CLI path through runMain — the same route a real invocation takes — so
// they must NOT call t.Parallel(): newRootCmd binds package globals
// (jsonOutput, noColor).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func TestExitCodeFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		started   bool
		wantCode  int
		wantPrint bool
	}{
		{"nil error", nil, true, exitOK, false},
		{"nil error before start", nil, false, exitOK, false},
		{"explicit exit code", exitCodeError{exitUsage}, true, exitUsage, false},
		{"wrapped explicit exit code", fmt.Errorf("wrap: %w", exitCodeError{exitRuntime}), true, exitRuntime, false},
		{"daemon unreachable", fmt.Errorf("connect: %w", daemon.ErrDaemonUnreachable), true, exitUnreachable, true},
		{"usage error (never started)", errors.New("unknown flag: --nope"), false, exitUsage, true},
		{"runtime error", errors.New("boom"), true, exitRuntime, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, print := exitCodeFor(tt.err, tt.started)
			if code != tt.wantCode || print != tt.wantPrint {
				t.Errorf("exitCodeFor(%v, %v) = (%d, %v), want (%d, %v)",
					tt.err, tt.started, code, print, tt.wantCode, tt.wantPrint)
			}
		})
	}
}

func TestRunMain_ExitCodes(t *testing.T) {
	dir := t.TempDir()
	badYAML := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(badYAML, []byte("::: definitely not yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("strikes: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(dir, "absent.yaml")
	noSocket := filepath.Join(dir, "no-daemon.sock")

	tests := []struct {
		name       string
		args       []string
		want       int
		wantStderr string // substring; empty = don't check
	}{
		{"success", []string{"version"}, exitOK, ""},
		{"help is success", []string{"--help"}, exitOK, ""},
		{"unknown command is usage", []string{"frobnicate"}, exitUsage, "unknown command"},
		{"unknown flag is usage", []string{"version", "--nope"}, exitUsage, "unknown flag"},
		{"extra args is usage", []string{"list", "extra-arg"}, exitUsage, ""},
		{"validate missing file is usage",
			[]string{"validate", "--config", absent, "--policy", absent}, exitUsage, ""},
		{"config show invalid yaml is runtime",
			[]string{"config", "show", "--config", badYAML, "--policy", policy}, exitRuntime, ""},
		{"daemon unreachable", []string{"list", "--socket", noSocket}, exitUnreachable, "daemon unreachable"},
		{"daemon unreachable on ban",
			[]string{"ban", "203.0.113.9", "--socket", noSocket}, exitUnreachable, "daemon unreachable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			got := runMain(tt.args, &out, &errOut)
			if got != tt.want {
				t.Errorf("runMain(%v) = %d, want %d\nstdout:\n%s\nstderr:\n%s",
					tt.args, got, tt.want, out.String(), errOut.String())
			}
			if tt.wantStderr != "" && !strings.Contains(errOut.String(), tt.wantStderr) {
				t.Errorf("runMain(%v) stderr = %q, want substring %q",
					tt.args, errOut.String(), tt.wantStderr)
			}
		})
	}
}

// TestRunMain_ExplicitCodePrintsNothing pins the contract that a RunE
// returning exitCodeError (validate & friends have already written their own
// diagnostics) does not get a redundant "error: exit code N" line on stderr.
func TestRunMain_ExplicitCodePrintsNothing(t *testing.T) {
	dir := t.TempDir()
	absent := filepath.Join(dir, "absent.yaml")

	var out, errOut bytes.Buffer
	code := runMain([]string{"validate", "--config", absent, "--policy", absent}, &out, &errOut)
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
	if strings.Contains(errOut.String(), "exit code") {
		t.Errorf("stderr leaked the internal exit-code error: %q", errOut.String())
	}
}

// TestRunMain_VersionJSON pins the stable JSON envelope of `version --json`.
func TestRunMain_VersionJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runMain([]string{"version", "--json"}, &out, &errOut); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, errOut.String())
	}
	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	for _, key := range []string{"version", "commit", "build_date"} {
		if _, ok := got[key]; !ok {
			t.Errorf("JSON output missing stable field %q: %v", key, got)
		}
	}
}
