package main

// Regression tests for issue #301: `list --json` and `list --allow --json`
// leaked the raw SocketResponse envelope ({"ok":true,"data":[...]}) while
// `list --audit --json` emitted a bare array — and the CLI reference's
// documented recipe (`list --json | jq '.[]'`) only works on the bare array.

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// mockListServer serves the "list" and "list_allow" verbs from a unix socket.
func mockListServer(t *testing.T, listData, allowData any) string {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "daemon.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})

	envelope := func(v any) daemon.SocketResponse {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return daemon.SocketResponse{OK: true, Data: raw}
	}

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
				case "list":
					_ = json.NewEncoder(c).Encode(envelope(listData))
				case "list_allow":
					_ = json.NewEncoder(c).Encode(envelope(allowData))
				}
			}(conn)
		}
	}()
	return sockPath
}

func TestListJSON_EmitsBareArray(t *testing.T) {
	sock := mockListServer(t,
		[]daemon.BanEntry{{IP: "203.0.113.42", Strike: 2, TTL: "1h", Reason: "test"}},
		[]daemon.AllowEntry{{Prefix: "192.0.2.0/24", Reason: "office"}})

	out, _, err := execRoot(t, "list", "--json", "--socket", sock)
	if err != nil {
		t.Fatalf("list --json: %v", err)
	}
	// The documented recipe requires a bare array: `... | jq '.[]'`.
	var entries []daemon.BanEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("list --json must emit a bare array (issue #301), got: %s", out)
	}
	if len(entries) != 1 || entries[0].IP != "203.0.113.42" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	// The envelope must be gone entirely.
	var env map[string]any
	if json.Unmarshal([]byte(out), &env) == nil {
		t.Fatalf("output still decodes as an envelope object: %s", out)
	}
}

func TestListAllowJSON_EmitsBareArray(t *testing.T) {
	sock := mockListServer(t,
		[]daemon.BanEntry{},
		[]daemon.AllowEntry{{Prefix: "192.0.2.0/24", Reason: "office"}})

	out, _, err := execRoot(t, "list", "--allow", "--json", "--socket", sock)
	if err != nil {
		t.Fatalf("list --allow --json: %v", err)
	}
	var entries []daemon.AllowEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("list --allow --json must emit a bare array (issue #301), got: %s", out)
	}
	if len(entries) != 1 || entries[0].Prefix != "192.0.2.0/24" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}
