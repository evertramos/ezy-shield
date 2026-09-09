// SPDX-License-Identifier: AGPL-3.0-only

package main

// Regression tests for issue #588: the blocked sets must not auto-merge
// (a merged interval has one timeout — the last add's — so a neighbour's
// ban lifetime was silently rewritten); pre-#588 sets are rebuilt once on
// start with their elements preserved; overlap refusals from a merge-less
// set keep the two legitimate shapes working.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/nftnames"
)

func TestInitTable_BlockedSetsDoNotAutoMerge(t *testing.T) {
	n := defaultNames()
	script := initTableScript(n)
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(line, "add set ") {
			continue
		}
		blocked := strings.Contains(line, " "+n.Set4+" ") || strings.Contains(line, " "+n.Set6+" ")
		merged := strings.Contains(line, "auto-merge")
		switch {
		case blocked && merged:
			t.Errorf("blocked set still auto-merges: %s", line)
		case blocked && !strings.Contains(line, "flags interval,timeout"):
			t.Errorf("blocked set lost interval/timeout flags: %s", line)
		case !blocked && !merged:
			t.Errorf("allowed/feed set unexpectedly lost auto-merge: %s", line)
		}
	}
}

// autoMergeListing renders `nft list set` output for one set, with or
// without the auto-merge flag line.
func autoMergeListing(set string, merged bool, elements string) []byte {
	flag := ""
	if merged {
		flag = "\t\tauto-merge\n"
	}
	return []byte("table inet ezyshield {\n\tset " + set + " {\n\t\ttype ipv4_addr\n\t\tflags interval,timeout\n" +
		flag + "\t\telements = { " + elements + " }\n\t}\n}\n")
}

func TestSetHasAutoMerge(t *testing.T) {
	n := defaultNames()
	stubListSetOutput(t, autoMergeListing(n.Set4, true, "192.0.2.10"), nil)
	if has, err := setHasAutoMerge(context.Background(), n, n.Set4); err != nil || !has {
		t.Fatalf("flagged set: has=%v err=%v, want true", has, err)
	}
	stubListSetOutput(t, autoMergeListing(n.Set4, false, "192.0.2.10"), nil)
	if has, err := setHasAutoMerge(context.Background(), n, n.Set4); err != nil || has {
		t.Fatalf("plain set: has=%v err=%v, want false", has, err)
	}
	stubListSetOutput(t, nil, fakeNftError(t, "Error: No such file or directory"))
	if has, err := setHasAutoMerge(context.Background(), n, n.Set4); err != nil || has {
		t.Fatalf("absent set: has=%v err=%v, want false and nil", has, err)
	}
	stubListSetOutput(t, nil, fakeNftError(t, "Error: Could not process rule: Operation not permitted"))
	if _, err := setHasAutoMerge(context.Background(), n, n.Set4); err == nil {
		t.Fatalf("EPERM must surface, not read as \"no flag\"")
	}
}

// TestInit_MigratesAutoMergeSet: a v4 set still flagged is rebuilt in one
// script — chains flushed, set deleted and re-declared without the flag,
// parsed elements re-added with remaining lifetimes, rules restored — and
// the v6 set without the flag is left alone.
func TestInit_MigratesAutoMergeSet(t *testing.T) {
	n := defaultNames()
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	srv.autoMergeFn = func(_ context.Context, _ nftnames.Names, set string) (bool, error) {
		return set == n.Set4, nil
	}
	srv.listFn = func(_ context.Context, _ nftnames.Names) ([]setElem, error) {
		return []setElem{
			{ip: "192.0.2.10", ttl: 4*time.Minute + 3*time.Second},
			{ip: "198.51.100.0/24"},
			{ip: "2001:db8::7", ttl: time.Hour}, // lives in the v6 set — not part of the v4 rebuild
		}, nil
	}
	if err := srv.init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	var migration string
	for _, sc := range mock.scripts {
		if strings.Contains(sc, "delete set ") {
			migration = sc
			break
		}
	}
	if migration == "" {
		t.Fatalf("no migration script issued; scripts: %v", mock.scripts)
	}
	for _, want := range []string{
		"flush chain inet ezyshield prerouting\n",
		"flush chain inet ezyshield input\n",
		"flush chain inet ezyshield forward\n",
		"delete set inet ezyshield " + n.Set4 + "\n",
		"add set inet ezyshield " + n.Set4 + " { type ipv4_addr ; flags interval,timeout ; }\n",
		"add element inet ezyshield " + n.Set4 + " { 192.0.2.10 timeout 243s }\n",
		"add element inet ezyshield " + n.Set4 + " { 198.51.100.0/24 }\n",
		"add rule inet ezyshield prerouting ip saddr @" + n.Set4 + " drop\n",
	} {
		if !strings.Contains(migration, want) {
			t.Errorf("migration script missing %q:\n%s", want, migration)
		}
	}
	if strings.Contains(migration, "2001:db8::7") {
		t.Errorf("v6 element re-added into the v4 set:\n%s", migration)
	}
	if strings.Contains(migration, "delete set inet ezyshield "+n.Set6) {
		t.Errorf("unflagged v6 set must not be rebuilt:\n%s", migration)
	}
	// Ordering inside the transaction: rules go only after the set exists again.
	if strings.Index(migration, "delete set") > strings.Index(migration, "add rule") {
		t.Errorf("rules re-added before the set was rebuilt:\n%s", migration)
	}
	// The cache reflects the rebuilt set.
	srv.mu.RLock()
	_, cached := srv.blocked["192.0.2.10"]
	srv.mu.RUnlock()
	if !cached {
		t.Errorf("cache not loaded after migration: %v", srv.blocked)
	}
}

func TestInit_NoMigrationWithoutFlag(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	srv.listFn = func(_ context.Context, _ nftnames.Names) ([]setElem, error) { return nil, nil }
	if err := srv.init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, sc := range mock.scripts {
		if strings.Contains(sc, "delete set ") {
			t.Fatalf("migration issued on an already-migrated set:\n%s", sc)
		}
	}
}

// overlapRunner fails every `add element` script matching failOn with
// nft's overlap message; everything else succeeds. All scripts are recorded.
func overlapRunner(mock *mockNftCalls, failOn func(script string) bool) nftRunner {
	return func(_ context.Context, script []byte) error {
		sc := string(script)
		mock.scripts = append(mock.scripts, sc)
		if strings.HasPrefix(sc, "add element") && failOn(sc) {
			return errors.New("nft -f: exit status 1\nError: interval overlaps with an existing one")
		}
		return nil
	}
}

// TestDispatch_Add_AddressCoveredByPrefix: an address inside an existing
// prefix ban is refused by the kernel but already enforced — the verb
// succeeds and the address is cached so reconcile stops re-adding it.
func TestDispatch_Add_AddressCoveredByPrefix(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	srv.run = overlapRunner(mock, func(sc string) bool { return strings.Contains(sc, "198.51.100.5") })

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "198.51.100.5", TTLSeconds: 300})
	if !resp.OK {
		t.Fatalf("covered address add failed: %s", resp.Error)
	}
	srv.mu.RLock()
	dl, ok := srv.blocked["198.51.100.5"]
	srv.mu.RUnlock()
	if !ok || dl.IsZero() {
		t.Fatalf("covered address not cached with its own deadline: ok=%v dl=%v", ok, dl)
	}
}

// TestDispatch_Add_PrefixAbsorbsContainedElements: a prefix ban that
// overlaps cached single elements deletes exactly those, retries the add
// once, and leaves unrelated elements alone.
func TestDispatch_Add_PrefixAbsorbsContainedElements(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)
	srv.mu.Lock()
	srv.blocked["198.51.100.5"] = time.Time{}
	srv.blocked["198.51.100.6"] = time.Now().Add(time.Hour)
	srv.blocked["198.51.100.128/25"] = time.Time{}
	srv.blocked["203.0.113.9"] = time.Time{}
	srv.mu.Unlock()
	first := true
	srv.run = overlapRunner(mock, func(sc string) bool {
		if strings.Contains(sc, "198.51.100.0/24") && first {
			first = false
			return true
		}
		return false
	})

	resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "198.51.100.0/24", TTLSeconds: 3600})
	if !resp.OK {
		t.Fatalf("prefix add failed: %s", resp.Error)
	}
	joined := strings.Join(mock.scripts, "")
	for _, want := range []string{
		"delete element inet ezyshield blocked { 198.51.100.5 }",
		"delete element inet ezyshield blocked { 198.51.100.6 }",
		"delete element inet ezyshield blocked { 198.51.100.128/25 }",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in scripts:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "delete element inet ezyshield blocked { 203.0.113.9 }") {
		t.Errorf("unrelated element deleted:\n%s", joined)
	}
	if strings.Count(joined, "add element inet ezyshield blocked { 198.51.100.0/24 timeout 3600s }") != 2 {
		t.Errorf("prefix add must be retried exactly once:\n%s", joined)
	}
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	for _, gone := range []string{"198.51.100.5", "198.51.100.6", "198.51.100.128/25"} {
		if _, ok := srv.blocked[gone]; ok {
			t.Errorf("absorbed element %s still cached", gone)
		}
	}
	if _, ok := srv.blocked["198.51.100.0/24"]; !ok {
		t.Errorf("prefix not cached after retry")
	}
	if _, ok := srv.blocked["203.0.113.9"]; !ok {
		t.Errorf("unrelated element evicted from cache")
	}
}

func TestParseSetElements_ReportsMergedIntervals(t *testing.T) {
	out := autoMergeListing("blocked", true, "192.0.2.10 timeout 5m expires 4m, 203.0.113.11-203.0.113.12 timeout 2m expires 1m, 198.51.100.0/24")
	els, skipped := parseSetElementsDetail(out)
	if len(els) != 2 {
		t.Fatalf("parsed %v, want the address and the prefix", els)
	}
	if len(skipped) != 1 || skipped[0] != "203.0.113.11-203.0.113.12" {
		t.Fatalf("skipped = %v, want the merged interval token", skipped)
	}
}

// TestDispatch_SpellingsShareOneCacheKey (issue #592): an add written as a
// /32 and a del written as a bare address must hit the same cache row and
// the same kernel element — otherwise the del removes the element and
// leaves a cache ghost. `list` reports the bare spelling.
func TestDispatch_SpellingsShareOneCacheKey(t *testing.T) {
	mock := &mockNftCalls{}
	srv := startTestServer(t, mock)

	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "add", IP: "192.0.2.10/32", TTLSeconds: 60}); !resp.OK {
		t.Fatalf("add: %s", resp.Error)
	}
	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "list"}); !resp.OK || len(resp.IPs) != 1 || resp.IPs[0] != "192.0.2.10" {
		t.Fatalf("list = %v, want [192.0.2.10]", resp.IPs)
	}
	if !strings.Contains(strings.Join(mock.scripts, ""), "add element inet ezyshield blocked { 192.0.2.10 timeout 60s }") {
		t.Fatalf("kernel add must use the bare spelling; scripts:\n%s", strings.Join(mock.scripts, ""))
	}
	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "del", IP: "192.0.2.10"}); !resp.OK {
		t.Fatalf("del: %s", resp.Error)
	}
	srv.mu.RLock()
	n := len(srv.blocked)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatalf("cache still holds %d row(s) after del of the other spelling: %v", n, srv.blocked)
	}
	// Allowlist verbs canonicalize the same way.
	if resp := doRPC(t, srv.sockPath(), enforce.Request{Verb: "allow_add", IP: "2001:db8::7/128"}); !resp.OK {
		t.Fatalf("allow_add: %s", resp.Error)
	}
	if !strings.Contains(strings.Join(mock.scripts, ""), "add element inet ezyshield allowed6 { 2001:db8::7 }") {
		t.Fatalf("allow_add must use the bare spelling; scripts:\n%s", strings.Join(mock.scripts, ""))
	}
}
