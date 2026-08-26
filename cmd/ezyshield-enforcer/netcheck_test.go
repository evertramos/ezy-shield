package main

// Tests for the "netcheck" verb (issue #213): the read-only netlink probe
// doctor uses to test the sandbox's effect rather than unit-file text.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/nftnames"
)

func TestNetcheck_OKWhenNetlinkWorks(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	srv.listFn = func(_ context.Context, _ nftnames.Names) ([]setElem, error) {
		return nil, nil // read-only list succeeded (empty set is fine)
	}
	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "netcheck"})
	if !resp.OK {
		t.Fatalf("netcheck failed: %s", resp.Error)
	}
	// Read-only contract: the probe must not have run any nft mutation.
	if len(mock.scripts) != 0 {
		t.Fatalf("netcheck ran mutating scripts: %v", mock.scripts)
	}
}

func TestNetcheck_SurfacesNetlinkFailure(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	srv.listFn = func(_ context.Context, _ nftnames.Names) ([]setElem, error) {
		return nil, errors.New("netlink: operation not permitted")
	}
	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "netcheck"})
	if resp.OK {
		t.Fatal("netcheck must fail when the sandbox blocks netlink")
	}
	if !strings.Contains(resp.Error, "netlink probe failed") ||
		!strings.Contains(resp.Error, "operation not permitted") {
		t.Fatalf("error = %q, want the probe failure with cause", resp.Error)
	}
}
