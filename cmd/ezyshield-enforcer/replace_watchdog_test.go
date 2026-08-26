// SPDX-License-Identifier: AGPL-3.0-only

package main

// Watchdog tests for the non-atomic replace path (issue #214): the dispatch
// "add" of an element the cache holds runs delete-then-add — two nft
// transactions. These tests inject the failure exactly between them ("kill
// the writer between steps", deterministically) and assert the state
// converges: either the previous element is restored with its remaining
// lifetime, or — when even the rollback fails — the cache agrees with the
// empty kernel so the daemon's reconcile re-adds from the store.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/evertramos/ezy-shield/internal/enforce"
)

// failingAddRunner wraps mockNftCalls: it records every script and fails
// "add element" scripts for ip according to failPlan (one bool per add
// attempt, in order; exhausted plan = succeed).
type failingAddRunner struct {
	mu       sync.Mutex
	inner    *mockNftCalls
	ip       string
	failPlan []bool
	adds     int
}

func (f *failingAddRunner) runner() nftRunner {
	base := f.inner.runner()
	return func(ctx context.Context, script []byte) error {
		s := string(script)
		if strings.Contains(s, "add element") && strings.Contains(s, f.ip) {
			f.mu.Lock()
			idx := f.adds
			f.adds++
			fail := idx < len(f.failPlan) && f.failPlan[idx]
			f.mu.Unlock()
			if fail {
				_ = base(ctx, script) // record the attempt like the others
				return errors.New("Error: Could not process rule: No buffer space available")
			}
		}
		return base(ctx, script)
	}
}

func TestReplace_InterruptedAddRollsBackPreviousElement(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	const ip = "192.0.2.90"
	// Add #1 (seed, timed): ok. Add #2 (the replace's new element): FAIL.
	// Add #3 (the rollback restore): ok.
	fr := &failingAddRunner{inner: mock, ip: ip, failPlan: []bool{false, true, false}}
	srv.run = fr.runner()

	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: ip, TTLSeconds: 300}); !resp.OK {
		t.Fatalf("seed add failed: %s", resp.Error)
	}
	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: ip, TTLSeconds: 0})
	if resp.OK {
		t.Fatal("interrupted replace must surface the add failure")
	}

	// The previous element must be back in the kernel with a timeout close
	// to its remaining lifetime, and the cache must still serve it.
	joined := strings.Join(mock.scripts, "\n")
	if !strings.Contains(joined, "delete element inet ezyshield blocked { "+ip+" }") {
		t.Fatalf("replace never deleted the old element:\n%s", joined)
	}
	last := mock.scripts[len(mock.scripts)-1]
	if !strings.Contains(last, "add element") || !strings.Contains(last, "timeout") {
		t.Fatalf("rollback must restore the element WITH its remaining timeout, last script:\n%s", last)
	}
	list := doRPC(t, srv.sockPath(), enforce.Request{Verb: "list"})
	if len(list.IPs) != 1 || list.IPs[0] != ip {
		t.Fatalf("cache must still hold the restored element, list = %v", list.IPs)
	}
}

func TestReplace_InterruptedAddAndFailedRollbackDropsGhost(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	const ip = "192.0.2.91"
	// Seed ok; replace add FAILS; rollback add FAILS too.
	fr := &failingAddRunner{inner: mock, ip: ip, failPlan: []bool{false, true, true}}
	srv.run = fr.runner()

	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: ip, TTLSeconds: 300}); !resp.OK {
		t.Fatalf("seed add failed: %s", resp.Error)
	}
	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: ip, TTLSeconds: 0})
	if resp.OK {
		t.Fatal("interrupted replace must surface the add failure")
	}

	// Kernel is empty for this ip and the rollback failed — the cache MUST
	// NOT keep a ghost claiming the element exists (the #383 failure class):
	// an honest empty list is what lets the daemon's reconcile re-add it.
	list := doRPC(t, srv.sockPath(), enforce.Request{Verb: "list"})
	if len(list.IPs) != 0 {
		t.Fatalf("cache holds a ghost after failed rollback, list = %v", list.IPs)
	}
}
