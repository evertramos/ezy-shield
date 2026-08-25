package main

// Regression tests for issue #383: a permanently-banned IP went unenforced
// for 12+ days on the dogfooding host because (A) the in-memory blocked cache
// never expired entries the KERNEL had already removed via nft's per-element
// `timeout`, so "list" served ghosts and the daemon's Sync skipped re-adds;
// and (B) re-adding an element whose old timer was still running did not
// replace the timer, so a strike upgrade (timed → permanent) silently kept
// the shorter expiry. Both paths are driven here with an injected clock —
// no sleeping, no real nft.

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/nftnames"
)

// fakeClock installs an injectable clock on srv and returns an advance
// function that is safe against the server goroutine (atomic offset).
func fakeClock(srv *Server) func(d time.Duration) {
	base := time.Now()
	var off atomic.Int64
	srv.nowFn = func() time.Time { return base.Add(time.Duration(off.Load())) }
	return func(d time.Duration) { off.Add(int64(d)) }
}

// TestDispatch_List_OmitsKernelExpiredEntries is the kylian reproduction:
// once a timed element's deadline passes, the kernel has removed it — "list"
// claiming it is still present makes Sync skip the re-add and the ban leaks
// silently until the helper restarts. Fails before the fix (the cache was a
// plain presence map with no notion of expiry).
func TestDispatch_List_OmitsKernelExpiredEntries(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	advance := fakeClock(srv)

	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "192.0.2.30", TTLSeconds: 300}); !resp.OK {
		t.Fatalf("add failed: %s", resp.Error)
	}
	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "list"}); len(resp.IPs) != 1 {
		t.Fatalf("live timed entry must be listed, got %v", resp.IPs)
	}

	advance(301 * time.Second) // kernel timer has fired by now

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "list"})
	if len(resp.IPs) != 0 {
		t.Fatalf("kernel-expired entry still reported by list — Sync would skip the re-add and the ban leaks (issue #383); got %v", resp.IPs)
	}

	// A later re-ban of the same IP must land in the kernel again.
	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "192.0.2.30", TTLSeconds: 0}); !resp.OK {
		t.Fatalf("re-add after kernel expiry failed: %s", resp.Error)
	}
	joined := strings.Join(mock.scripts, "\n")
	if !strings.Contains(joined, "add element inet ezyshield blocked { 192.0.2.30 }") {
		t.Errorf("permanent re-add never reached nft:\n%s", joined)
	}
}

// TestDispatch_Add_PermanentReplacesTimedElement covers path B: nft's `add
// element` keeps an existing element's old timer (auto-merge), so upgrading a
// live timed ban to permanent must delete-then-add — otherwise the permanent
// ban dies with the old timer.
func TestDispatch_Add_PermanentReplacesTimedElement(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	advance := fakeClock(srv)

	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "192.0.2.40", TTLSeconds: 300}); !resp.OK {
		t.Fatalf("timed add failed: %s", resp.Error)
	}
	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "192.0.2.40", TTLSeconds: 0}); !resp.OK {
		t.Fatalf("permanent re-add failed: %s", resp.Error)
	}

	joined := strings.Join(mock.scripts, "\n")
	del := strings.Index(joined, "delete element inet ezyshield blocked { 192.0.2.40 }")
	permAdd := strings.LastIndex(joined, "add element inet ezyshield blocked { 192.0.2.40 }")
	if del < 0 {
		t.Fatalf("re-add of a live element must delete it first (old timer would survive auto-merge):\n%s", joined)
	}
	if permAdd < del {
		t.Fatalf("permanent add must come after the delete:\n%s", joined)
	}

	// The upgrade is permanent: way past the original timer, list still has it.
	advance(48 * time.Hour)
	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "list"}); len(resp.IPs) != 1 {
		t.Fatalf("permanent upgrade lost with the old timer, list = %v", resp.IPs)
	}
}

// TestDispatch_Add_ReplaceToleratesAbsentElement: the delete half of the
// replace may race the kernel timer (cache says present, kernel already
// expired it). The absent signal must not fail the add.
func TestDispatch_Add_ReplaceToleratesAbsentElement(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	// Runner that fails deletes the way nft reports missing elements and
	// records everything else like mockNftCalls.
	inner := mock.runner()
	srv.run = func(ctx context.Context, script []byte) error {
		if strings.HasPrefix(string(script), "delete element") {
			return errors.New("Error: Could not process rule: No such file or directory")
		}
		return inner(ctx, script)
	}

	srv.mu.Lock()
	srv.blocked["192.0.2.50"] = time.Time{} // cache believes it is present
	srv.mu.Unlock()

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "192.0.2.50", TTLSeconds: 0})
	if !resp.OK {
		t.Fatalf("add must tolerate the element being already gone from the kernel: %s", resp.Error)
	}
	joined := strings.Join(mock.scripts, "\n")
	if !strings.Contains(joined, "add element inet ezyshield blocked { 192.0.2.50 }") {
		t.Errorf("add never reached nft after tolerated absent delete:\n%s", joined)
	}
}

// TestInit_LoadsExpiryDeadlinesFromKernel: boot loads each element's
// remaining lifetime (the `expires` annotation), so entries the kernel will
// expire soon do not become immortal cache ghosts across a helper restart.
func TestInit_LoadsExpiryDeadlinesFromKernel(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	advance := fakeClock(srv)
	srv.listFn = func(_ context.Context, _ nftnames.Names) ([]setElem, error) {
		return []setElem{
			{ip: "192.0.2.60", ttl: 5 * time.Minute}, // timed: 5m left on the kernel timer
			{ip: "192.0.2.61", ttl: 0},               // permanent
		}, nil
	}
	if err := srv.init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "list"}); len(resp.IPs) != 2 {
		t.Fatalf("both loaded entries must be live at boot, got %v", resp.IPs)
	}

	advance(6 * time.Minute)

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "list"})
	if len(resp.IPs) != 1 || resp.IPs[0] != "192.0.2.61" {
		t.Fatalf("after the kernel timer fires only the permanent entry may remain, got %v", resp.IPs)
	}
}

func TestParseNftDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{in: "4m3s", want: 4*time.Minute + 3*time.Second},
		{in: "6d23h59m12s", want: 6*24*time.Hour + 23*time.Hour + 59*time.Minute + 12*time.Second},
		{in: "2d", want: 48 * time.Hour},
		{in: "500ms", want: 500 * time.Millisecond},
		{in: "garbage", err: true},
		{in: "xd4m", err: true},
	}
	for _, c := range cases {
		got, err := parseNftDuration(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseNftDuration(%q): expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseNftDuration(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseNftDuration(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestElemTTL_UnparseableAnnotationFailsSafe: an `expires` value we cannot
// parse must map to about-to-expire (1s), NEVER permanent — the fail-safe
// direction is a redundant re-add by the next Sync, not an immortal ghost.
func TestElemTTL_UnparseableAnnotationFailsSafe(t *testing.T) {
	if got := elemTTL([]string{"timeout", "5m", "expires", "not-a-duration"}); got != time.Second {
		t.Errorf("unparseable expires = %v, want the 1s fail-safe", got)
	}
	if got := elemTTL([]string{"timeout", "5m"}); got != 5*time.Minute {
		t.Errorf("timeout-only annotation = %v, want 5m", got)
	}
	if got := elemTTL(nil); got != 0 {
		t.Errorf("no annotation = %v, want 0 (permanent)", got)
	}
}
