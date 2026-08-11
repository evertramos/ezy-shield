package main

// cache_consistency_test.go — regression tests for issue #418 (family: #383,
// #318): after strike→expire→re-ban cycles on a native IPv6 address, the
// enforcer's in-memory blocked cache must never claim an element the kernel
// does not have. The cache backs the `list` verb, `list` backs
// NftablesEnforcer.Sync's reconcile, so a cache-present/kernel-absent
// divergence makes every future Sync skip the re-add: the ban leaks
// silently until the helper restarts (exactly the sustained
// `ban_ineffective` signature from the 2026-08-06 kylian audit).
//
// The tests drive dispatch against fakeNft, a stateful stand-in for the
// kernel side whose semantics were verified against real nftables v1.0.6 /
// kernel 6.1 (the kylian stack) in an unprivileged netns:
//   - `delete element` of an absent element fails with
//     "Error: element does not exist" (→ errElementAbsent path);
//   - `add element` of an element already present in an
//     interval,timeout,auto-merge set succeeds and REFRESHES the timeout
//     (userspace auto-merge rewrites the element);
//   - per-element `timeout` removes the element without any notification
//     to the helper (nft-native expiry, issue #39).

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforce"
)

// fakeNft models the kernel-side nftables state mutated by the enforcer's
// generated scripts. Only the script shapes nft.go emits are understood;
// anything else (initTable's table/chain/rule setup) is accepted as a no-op.
type fakeNft struct {
	mu   sync.Mutex
	now  time.Time
	sets map[string]map[string]time.Time // set name → element → expiry (zero = permanent)

	// onAddApplied, when armed, is invoked after an `add element` script has
	// been applied to the fake kernel but BEFORE the runner returns — i.e.
	// inside the window where the real helper has mutated the kernel but not
	// yet its blocked cache. Used to force the cross-connection interleaving
	// of TestDispatch_ConcurrentDelAdd_CacheNeverDivergesFromKernel.
	addHookArmed atomic.Bool
	onAddApplied func()
}

func newFakeNft() *fakeNft {
	return &fakeNft{
		now:  time.Unix(1_754_000_000, 0), // arbitrary fixed epoch
		sets: make(map[string]map[string]time.Time),
	}
}

// advance moves the fake clock and garbage-collects expired elements,
// mirroring the kernel's timeout GC.
func (f *fakeNft) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	for _, set := range f.sets {
		for el, exp := range set {
			if !exp.IsZero() && !exp.After(f.now) {
				delete(set, el)
			}
		}
	}
}

// elements returns the sorted live elements of a set.
func (f *fakeNft) elements(set string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for el, exp := range f.sets[set] {
		if exp.IsZero() || exp.After(f.now) {
			out = append(out, el)
		}
	}
	sort.Strings(out)
	return out
}

// expiry returns the expiry time of an element and whether it is present.
func (f *fakeNft) expiry(set, el string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, ok := f.sets[set][el]
	return exp, ok
}

// runner returns an nftRunner applying scripts to the fake state.
func (f *fakeNft) runner() nftRunner {
	return func(_ context.Context, script []byte) error {
		addApplied, err := f.apply(string(script))
		if addApplied && f.addHookArmed.Load() && f.onAddApplied != nil {
			f.onAddApplied()
		}
		return err
	}
}

// apply executes one script against the fake state. Returns whether an
// `add element` line was applied, and the first error hit (nft -f is
// atomic per script, but the shapes under test are all single-statement).
func (f *fakeNft) apply(script string) (addApplied bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "add element "):
			set, el, ttl, perr := parseElementLine(strings.TrimPrefix(line, "add element "))
			if perr != nil {
				return addApplied, perr
			}
			exp := time.Time{}
			if ttl > 0 {
				exp = f.now.Add(ttl)
			}
			if f.sets[set] == nil {
				f.sets[set] = make(map[string]time.Time)
			}
			// Verified real-nft semantics (v1.0.6, interval,timeout,
			// auto-merge): re-adding a live element succeeds and refreshes
			// its timeout.
			f.sets[set][el] = exp
			addApplied = true
		case strings.HasPrefix(line, "delete element "):
			set, el, _, perr := parseElementLine(strings.TrimPrefix(line, "delete element "))
			if perr != nil {
				return addApplied, perr
			}
			exp, ok := f.sets[set][el]
			if !ok || (!exp.IsZero() && !exp.After(f.now)) {
				// Verified real-nft wording; must trip nftAbsentSignals.
				return addApplied, fmt.Errorf("nft -f: exit status 1\nError: element does not exist")
			}
			delete(f.sets[set], el)
		case strings.HasPrefix(line, "flush set "):
			// "flush set inet ezyshield blocked" → last field is the set.
			fields := strings.Fields(line)
			delete(f.sets, fields[len(fields)-1])
		default:
			// initTable plumbing (add table/set/chain/rule, flush chain,
			// delete table): accepted, not modeled.
		}
	}
	return addApplied, nil
}

// parseElementLine parses `inet ezyshield <set> { <el> [timeout <N>s] }`.
func parseElementLine(rest string) (set, el string, ttl time.Duration, err error) {
	head, body, ok := strings.Cut(rest, "{")
	if !ok {
		return "", "", 0, fmt.Errorf("fakeNft: malformed element line %q", rest)
	}
	hf := strings.Fields(head) // family table set
	if len(hf) != 3 {
		return "", "", 0, fmt.Errorf("fakeNft: malformed element head %q", head)
	}
	body = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(body), "}"))
	bf := strings.Fields(body) // el [timeout Ns]
	if len(bf) == 0 {
		return "", "", 0, fmt.Errorf("fakeNft: empty element body in %q", rest)
	}
	if len(bf) == 3 && bf[1] == "timeout" {
		d, derr := time.ParseDuration(bf[2])
		if derr != nil {
			return "", "", 0, fmt.Errorf("fakeNft: bad timeout in %q: %w", rest, derr)
		}
		ttl = d
	}
	return hf[2], bf[0], ttl, nil
}

// newFakeServer builds a Server wired to the fake kernel, without a socket
// (tests call dispatch directly, mirroring the per-connection goroutines
// of Server.handle).
func newFakeServer(t *testing.T, f *fakeNft) *Server {
	t.Helper()
	srv := newServer("unused.sock", f.runner())
	srv.runSs = func(_ context.Context, _ []string) error { return nil }
	return srv
}

// listIPs runs the list verb and returns its sorted contents.
func listIPs(t *testing.T, srv *Server) []string {
	t.Helper()
	resp := srv.dispatch(context.Background(), enforce.Request{Verb: "list"})
	if !resp.OK {
		t.Fatalf("list failed: %s", resp.Error)
	}
	ips := append([]string(nil), resp.IPs...)
	sort.Strings(ips)
	return ips
}

// TestDispatch_IPv6_ExpireRebanCycles_CacheMatchesKernel drives a native
// IPv6 address through the exact strike ladder cycle from the #418 incident
// (5min → 1h → 24h in quick succession) and asserts after every step that
// the helper's cache and the (fake) kernel agree. Covers, sequentially:
//   - cycle 1: kernel-native timeout expiry, then the daemon's post-expire
//     reconcile del (errElementAbsent → CodeAlreadyAbsent) before re-ban;
//   - cycle 2: reconcile del arriving while the element is still live
//     (pre-expiry del), then re-ban;
//   - cycle 3: re-ban with NO del at all — the cache still holds the entry
//     from cycle 2's ban whose kernel element timed out natively (the
//     stale-cache re-add of hypothesis "cache desync after expire→re-add").
func TestDispatch_IPv6_ExpireRebanCycles_CacheMatchesKernel(t *testing.T) {
	ctx := context.Background()
	fake := newFakeNft()
	srv := newFakeServer(t, fake)
	const ip = "2001:db8::736e" // RFC 3849 documentation range

	mustAdd := func(ttl int64) {
		t.Helper()
		resp := srv.dispatch(ctx, enforce.Request{Verb: "add", IP: ip, TTLSeconds: ttl})
		if !resp.OK {
			t.Fatalf("add ttl=%d failed: %s", ttl, resp.Error)
		}
	}
	assertConsistent := func(stage string) {
		t.Helper()
		kernel := fake.elements("blocked6")
		cache := listIPs(t, srv)
		if fmt.Sprint(kernel) != fmt.Sprint(cache) {
			t.Fatalf("%s: cache/kernel desync: kernel=%v cache(list)=%v", stage, kernel, cache)
		}
	}

	// Cycle 1: strike 1 (5 min), nft-native expiry, post-expire del, re-ban.
	mustAdd(300)
	if got := fake.elements("blocked6"); len(got) != 1 {
		t.Fatalf("strike1: expected element in blocked6 (v6 set), got %v; v4 set=%v",
			got, fake.elements("blocked"))
	}
	assertConsistent("strike1 banned")
	fake.advance(301 * time.Second) // kernel timeout fires; cache still holds ip
	resp := srv.dispatch(ctx, enforce.Request{Verb: "del", IP: ip})
	if !resp.OK || resp.Code != enforce.CodeAlreadyAbsent {
		t.Fatalf("post-expire del: want OK+already_absent, got ok=%v code=%q err=%q",
			resp.OK, resp.Code, resp.Error)
	}
	assertConsistent("strike1 expired+reconciled")

	// Cycle 2: strike 2 (1 h), reconcile del lands while still live.
	mustAdd(3600)
	assertConsistent("strike2 banned")
	fake.advance(3599 * time.Second)
	resp = srv.dispatch(ctx, enforce.Request{Verb: "del", IP: ip})
	if !resp.OK || resp.Code != "" {
		t.Fatalf("pre-expiry del: want plain OK, got ok=%v code=%q err=%q", resp.OK, resp.Code, resp.Error)
	}
	assertConsistent("strike2 deleted")

	// Re-ban for cycle 3 setup, then let the kernel expire it natively with
	// NO del: the cache legitimately still holds the ip (known benign
	// staleness reconciled by Sync) — the re-ban add must land in the
	// kernel regardless of the stale cache entry.
	mustAdd(3600)
	fake.advance(3601 * time.Second)
	if got := fake.elements("blocked6"); len(got) != 0 {
		t.Fatalf("pre strike3: kernel should have expired the element, got %v", got)
	}

	// Cycle 3: strike 3 (24 h) — the incident's leaking rung.
	mustAdd(86400)
	assertConsistent("strike3 banned")
	exp, ok := fake.expiry("blocked6", ip)
	if !ok {
		t.Fatalf("strike3: element missing from kernel after re-ban")
	}
	if want := fake.now.Add(86400 * time.Second); !exp.Equal(want) {
		t.Fatalf("strike3: kernel expiry = %v, want %v (24h)", exp, want)
	}
	// The whole point of the incident: the ban must still hold hours later.
	fake.advance(7*time.Hour + 30*time.Minute)
	if got := fake.elements("blocked6"); len(got) != 1 {
		t.Fatalf("strike3 +7.5h: ban leaked — kernel=%v, want [%s]", got, ip)
	}
	assertConsistent("strike3 +7.5h")
}

// TestDispatch_IPv6_RebanBeforeKernelExpiry_TimeoutRefreshed pins the
// re-ban-races-native-timeout window: the escalation add lands while the
// previous rung's element is still live with residual timeout. Real nft
// (interval,timeout,auto-merge — verified on v1.0.6/kernel 6.1) refreshes
// the timeout; the helper must end up with kernel and cache agreeing on a
// 24h element, not a seconds-residual one.
func TestDispatch_IPv6_RebanBeforeKernelExpiry_TimeoutRefreshed(t *testing.T) {
	ctx := context.Background()
	fake := newFakeNft()
	srv := newFakeServer(t, fake)
	const ip = "2001:db8::736e"

	if resp := srv.dispatch(ctx, enforce.Request{Verb: "add", IP: ip, TTLSeconds: 3600}); !resp.OK {
		t.Fatalf("strike2 add failed: %s", resp.Error)
	}
	fake.advance(3598 * time.Second) // 2s residual on the old rung
	if resp := srv.dispatch(ctx, enforce.Request{Verb: "add", IP: ip, TTLSeconds: 86400}); !resp.OK {
		t.Fatalf("strike3 re-add failed: %s", resp.Error)
	}
	fake.advance(10 * time.Second) // old residual elapses
	if got := fake.elements("blocked6"); len(got) != 1 {
		t.Fatalf("re-ban lost to the old rung's timeout: kernel=%v, want [%s]", got, ip)
	}
	if got, want := listIPs(t, srv), []string{ip}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("list = %v, want %v", got, want)
	}
}

// TestDispatch_ConcurrentDelAdd_CacheNeverDivergesFromKernel reproduces the
// #418 sustained-leak mechanism: a re-ban `add` and a stale post-expire
// `del` for the SAME address arrive on concurrent connections (pipeline
// Ban vs expiry-tick / probe Sync in the daemon). The kernel serializes
// the nft executions as add-then-del, but the helper's cache writes land
// del-then-add: final state kernel=absent, cache=present. From then on
// `list` reports the ban as enforced, NftablesEnforcer.Sync never re-adds
// it, and the leak persists until the helper restarts — the exact
// signature of the kylian rc.27 incident (and #383).
//
// The interleaving is forced deterministically: the fake kernel parks the
// add-connection inside the runner (kernel mutated, cache not yet), lets
// the del run to completion, then releases the add.
func TestDispatch_ConcurrentDelAdd_CacheNeverDivergesFromKernel(t *testing.T) {
	ctx := context.Background()
	fake := newFakeNft()
	srv := newFakeServer(t, fake)
	const ip = "2001:db8::736e"

	// Realistic pre-state: strike-2 ban whose kernel element nft-expired;
	// the cache still holds it (benign staleness pending reconcile).
	if resp := srv.dispatch(ctx, enforce.Request{Verb: "add", IP: ip, TTLSeconds: 3600}); !resp.OK {
		t.Fatalf("seed add failed: %s", resp.Error)
	}
	fake.advance(3601 * time.Second)

	applied := make(chan struct{})
	release := make(chan struct{})
	fake.onAddApplied = func() {
		fake.addHookArmed.Store(false) // fire once
		close(applied)
		<-release
	}
	fake.addHookArmed.Store(true)

	// Connection A: the strike-3 re-ban (24 h). Parks after the kernel add.
	addDone := make(chan enforce.Response, 1)
	go func() {
		addDone <- srv.dispatch(ctx, enforce.Request{Verb: "add", IP: ip, TTLSeconds: 86400})
	}()
	<-applied

	// Connection B: the stale reconcile del (computed against a want-list
	// snapshot that predates the re-ban). With serialized mutations it
	// blocks until A completes; with the bug it interleaves.
	delDone := make(chan enforce.Response, 1)
	go func() {
		delDone <- srv.dispatch(ctx, enforce.Request{Verb: "del", IP: ip})
	}()
	select {
	case <-delDone:
		// Buggy interleaving happened: del ran while add was parked
		// between its kernel write and its cache write.
		delDone <- enforce.Response{OK: true} // refill for the drain below
	case <-time.After(200 * time.Millisecond):
		// del is (correctly) waiting for add to finish.
	}
	close(release)

	if resp := <-addDone; !resp.OK {
		t.Fatalf("re-ban add failed: %s", resp.Error)
	}
	if resp := <-delDone; !resp.OK {
		t.Fatalf("del failed: %s", resp.Error)
	}

	// Invariant (issue #418): whatever the interleaving, the cache the
	// `list` verb serves must match the kernel. A divergence here is the
	// sustained-leak state: Sync trusts `list`, so a cache-present/
	// kernel-absent element is never re-added until restart.
	kernel := fake.elements("blocked6")
	cache := listIPs(t, srv)
	if fmt.Sprint(kernel) != fmt.Sprint(cache) {
		t.Fatalf("cache/kernel desync after concurrent del+add: kernel=%v cache(list)=%v — "+
			"a banned IP the kernel is not blocking would stay invisible to Sync until restart (issue #418)",
			kernel, cache)
	}
}
