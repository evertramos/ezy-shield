package main

// Tests for `ezyshield disable` (issue #176): the --local-only break-glass
// path against a fake enforcer helper socket, and the confirmation gate.

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/enforce"
)

// fakeHelperSocket answers one request on a unix socket and records the verb.
func fakeHelperSocket(t *testing.T, resp enforce.Response) (path string, gotVerb *string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "enf.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	verb := new(string)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		var req enforce.Request
		_ = json.NewDecoder(conn).Decode(&req)
		*verb = req.Verb
		_ = json.NewEncoder(conn).Encode(resp)
	}()
	return path, verb
}

func runDisable(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append([]string{"disable"}, args...))
	err := root.Execute()
	return out.String(), errb.String(), err
}

func TestDisable_LocalOnlyFlushesViaHelper(t *testing.T) {
	sock, verb := fakeHelperSocket(t, enforce.Response{OK: true})
	out, _, err := runDisable(t, "", "--local-only", "--yes", "--enforcer-socket", sock)
	if err != nil {
		t.Fatalf("disable --local-only: %v", err)
	}
	if *verb != "flush" {
		t.Fatalf("helper received verb %q, want flush", *verb)
	}
	if !strings.Contains(out, "flushed") || !strings.Contains(out, "reconcile") {
		t.Fatalf("output must confirm the flush and warn about reconcile:\n%s", out)
	}
}

func TestDisable_ConfirmationAbortsByDefault(t *testing.T) {
	sock, verb := fakeHelperSocket(t, enforce.Response{OK: true})
	out, _, err := runDisable(t, "n\n", "--local-only", "--enforcer-socket", sock)
	if err != nil {
		t.Fatalf("declined run must not error: %v", err)
	}
	if !strings.Contains(out, "aborted") {
		t.Fatalf("declined confirmation must abort:\n%s", out)
	}
	if *verb != "" {
		t.Fatalf("helper was called (%q) after the operator declined", *verb)
	}
}

func TestDisable_AllAndLocalOnlyMutuallyExclusive(t *testing.T) {
	_, _, err := runDisable(t, "", "--all", "--local-only", "--yes")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v, want mutual-exclusion rejection", err)
	}
}

func TestDisable_AllUnreachableDaemonPrintsFallback(t *testing.T) {
	_, errOut, err := runDisable(t, "", "--all", "--yes",
		"--socket", filepath.Join(t.TempDir(), "missing.sock"))
	if err == nil {
		t.Fatal("unreachable daemon must error")
	}
	for _, want := range []string{"manual recovery", "nft flush set inet ezyshield blocked", "systemctl stop ezyshield"} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("fallback output lacks %q:\n%s", want, errOut)
		}
	}
}
