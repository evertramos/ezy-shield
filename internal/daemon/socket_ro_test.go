// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Tests for the control-socket read/write split (issue #212): the verb
// matrix per access tier, deny-by-default for unknown verbs on the
// read-only socket, audit attribution for mutating verbs, and the real
// two-socket serving path.

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/store"
)

// callSocketScoped mirrors callSocket but dispatches through the scoped
// entry point, so tests can exercise the read-only tier.
func callSocketScoped(t *testing.T, d *Daemon, req SocketRequest, readOnly bool) SocketResponse {
	t.Helper()
	ctx := context.Background()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.handleConnScoped(ctx, server, readOnly)
	}()
	if err := json.NewEncoder(client).Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var resp SocketResponse
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	_ = client.Close()
	<-done
	return resp
}

// TestReadOnlySocket_VerbMatrix drives every known verb through both tiers:
// read verbs answer on the read-only tier; every mutating verb is refused
// there with the operator-socket hint, and unknown verbs are refused too
// (deny by default). subscribe is exercised separately (long-lived stream).
func TestReadOnlySocket_VerbMatrix(t *testing.T) {
	captureSlog(t)
	d := newTestDaemonForSocket(t, false)

	reads := []string{"status", "list", "list_allow", "events", "report", "metrics", "feeds_status"}
	writes := []string{"arm", "arm_keep", "disarm", "ban", "unban", "allow", "unallow", "feeds_refresh", "disable_all", "prune"}

	// The two sets plus subscribe must cover the daemon's whole verb
	// vocabulary — a new verb that forgets to classify itself fails here.
	if got, want := len(reads)+len(writes)+1, len(readOnlyVerbs)+len(mutatingVerbs); got != want {
		t.Fatalf("verb matrix out of sync with classification maps: %d verbs tested, %d classified", got, want)
	}

	for _, verb := range reads {
		resp := callSocketScoped(t, d, SocketRequest{Verb: verb}, true)
		if strings.Contains(resp.Error, "read-only socket") {
			t.Errorf("read verb %q must be served on the read-only socket, got error: %s", verb, resp.Error)
		}
	}
	for _, verb := range writes {
		resp := callSocketScoped(t, d, SocketRequest{Verb: verb, IP: "203.0.113.5"}, true)
		if !strings.Contains(resp.Error, "read-only socket") {
			t.Errorf("write verb %q must be refused on the read-only socket, got: %+v", verb, resp)
		}
		// The same verb must still dispatch on the operator tier (any
		// response but the read-only refusal counts — handler-level
		// validation errors are fine).
		full := callSocketScoped(t, d, SocketRequest{Verb: verb, IP: "203.0.113.5"}, false)
		if strings.Contains(full.Error, "read-only socket") {
			t.Errorf("write verb %q wrongly refused on the operator socket: %s", verb, full.Error)
		}
	}

	// Deny by default: an unknown (future) verb is refused on the read-only
	// tier BEFORE reaching the dispatcher.
	resp := callSocketScoped(t, d, SocketRequest{Verb: "future_verb"}, true)
	if !strings.Contains(resp.Error, "read-only socket") {
		t.Errorf("unknown verbs must be denied by default on the read-only socket, got: %s", resp.Error)
	}
}

// TestMutatingVerb_AuditsPeer: a mutating verb on the operator socket lands
// one socket_cmd audit entry naming the verb (net.Pipe carries no
// SO_PEERCRED, so attribution degrades to peer=unknown — the entry itself
// must still be written).
func TestMutatingVerb_AuditsPeer(t *testing.T) {
	captureSlog(t)
	d := newTestDaemonForSocket(t, false)
	ctx := context.Background()

	_ = callSocketScoped(t, d, SocketRequest{Verb: "disarm"}, false)

	entries, err := d.store.(auditLister).ListAuditLog(ctx, 50)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Op == "socket_cmd" && strings.Contains(e.Reason, "verb=disarm") &&
			strings.Contains(e.Reason, "peer=unknown") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a socket_cmd audit entry for disarm, got %+v", entries)
	}
}

// TestReadOnlyRefusal_Audited: a viewer attempting a write verb is itself a
// security event and must be journaled with ok=false.
func TestReadOnlyRefusal_Audited(t *testing.T) {
	captureSlog(t)
	d := newTestDaemonForSocket(t, false)
	ctx := context.Background()

	_ = callSocketScoped(t, d, SocketRequest{Verb: "unban", IP: "203.0.113.6"}, true)

	entries, err := d.store.(auditLister).ListAuditLog(ctx, 50)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Op == "socket_cmd" && strings.Contains(e.Reason, "verb=unban") &&
			strings.Contains(e.Reason, "ok=false") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an audited refusal for unban on the read-only socket, got %+v", entries)
	}
}

// auditLister narrows the store to what these tests need; the assertion
// matches the concrete *store.DB behind the daemonStore interface.
type auditLister interface {
	ListAuditLog(ctx context.Context, limit int) ([]store.AuditEntry, error)
}

// waitForSocket polls path with a status call until the daemon answers.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := Call(context.Background(), path, SocketRequest{Verb: "status"}); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s did not come up", path)
}

// TestServeSocket_TwoTiers exercises the real serving path: both sockets
// bound, the RO socket answering read verbs and refusing writes, with real
// SO_PEERCRED attribution in the audit journal.
func TestServeSocket_TwoTiers(t *testing.T) {
	captureSlog(t)
	d := newTestDaemonForSocket(t, false)
	dir := t.TempDir()
	d.socketPath = filepath.Join(dir, "ez.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.serveSocket(ctx)

	waitForSocket(t, d.socketPath)
	roPath := ROSocketPath(d.socketPath)
	waitForSocket(t, roPath)

	// Read verb on both tiers.
	if _, err := Call(ctx, d.socketPath, SocketRequest{Verb: "status"}); err != nil {
		t.Fatalf("status on operator socket: %v", err)
	}
	if _, err := Call(ctx, roPath, SocketRequest{Verb: "status"}); err != nil {
		t.Fatalf("status on read-only socket: %v", err)
	}

	// Write verb: refused on RO, dispatched on operator.
	if _, err := Call(ctx, roPath, SocketRequest{Verb: "disarm"}); err == nil ||
		!strings.Contains(err.Error(), "read-only socket") {
		t.Fatalf("disarm on read-only socket: err = %v, want read-only refusal", err)
	}
	if _, err := Call(ctx, d.socketPath, SocketRequest{Verb: "disarm"}); err != nil {
		t.Fatalf("disarm on operator socket: %v", err)
	}

	// Real unix connections carry SO_PEERCRED on Linux: the audit entries
	// must attribute the requests to this process's uid/gid.
	entries, err := d.store.(auditLister).ListAuditLog(ctx, 50)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if runtime.GOOS == "linux" {
		sawAttributed := false
		for _, e := range entries {
			if e.Op == "socket_cmd" && strings.Contains(e.Reason, "peer_uid=") {
				sawAttributed = true
			}
		}
		if !sawAttributed {
			t.Errorf("expected SO_PEERCRED-attributed socket_cmd entries, got %+v", entries)
		}
	}
}
