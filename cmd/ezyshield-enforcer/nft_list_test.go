// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/nftnames"
)

// fakeNftError produces a real *exec.ExitError whose Stderr carries msg —
// exactly what cmd.Output() returns when nft exits non-zero and prints to
// stderr. Fabricating exec.ExitError directly is not possible (it needs a
// live *os.ProcessState), so we run a tiny failing shell command.
func fakeNftError(t *testing.T, msg string) error {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "sh", "-c", `printf '%s\n' "$NFT_TEST_MSG" >&2; exit 1`)
	cmd.Env = append(os.Environ(), "NFT_TEST_MSG="+msg)
	_, err := cmd.Output()
	if err == nil {
		t.Fatal("expected the stub command to fail")
	}
	return err
}

func stubListSetOutput(t *testing.T, out []byte, err error) {
	t.Helper()
	orig := listSetOutput
	t.Cleanup(func() { listSetOutput = orig })
	listSetOutput = func(_ context.Context, _, _, _ string) ([]byte, error) {
		return out, err
	}
}

// TestListSet_RealErrorSurfaces reproduces issue #318: every non-zero nft
// exit was treated as "empty set" (the catch-all matched any ExitError, whose
// Error() is always "exit status N"), so genuine failures — EPERM, missing
// CAP_NET_ADMIN, broken table state — returned (nil, nil) and silently
// desynced the helper's blocked cache from the kernel.
func TestListSet_RealErrorSurfaces(t *testing.T) {
	stubListSetOutput(t, nil, fakeNftError(t, "Error: Could not process rule: Operation not permitted"))

	names, err := nftnames.Resolve("", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := listSet(context.Background(), names, names.Set4); err == nil {
		t.Fatal("real nft failure must surface, got nil error (blocked cache would silently desync)")
	}
}

// TestListSet_AbsentSetTreatedAsEmpty keeps the one benign case: the set not
// existing yet. nft reports that on stderr; it must map to (nil, nil).
func TestListSet_AbsentSetTreatedAsEmpty(t *testing.T) {
	stubListSetOutput(t, nil, fakeNftError(t, "Error: No such file or directory"))

	names, err := nftnames.Resolve("", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	ips, err := listSet(context.Background(), names, names.Set4)
	if err != nil {
		t.Fatalf("absent set must be treated as empty, got error: %v", err)
	}
	if len(ips) != 0 {
		t.Fatalf("absent set must yield no elements, got %v", ips)
	}
}

// TestListSet_ParsesElements guards the success path through the injectable
// runner: stdout parsing must be unaffected by the refactor.
func TestListSet_ParsesElements(t *testing.T) {
	out := []byte(`table inet ezyshield {
	set blocked4 {
		type ipv4_addr
		flags interval,timeout
		elements = { 192.0.2.10 timeout 5m expires 4m3s, 198.51.100.0/24 }
	}
}
`)
	stubListSetOutput(t, out, nil)

	names, err := nftnames.Resolve("", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	els, err := listSet(context.Background(), names, names.Set4)
	if err != nil {
		t.Fatalf("listSet: %v", err)
	}
	// Remaining lifetime comes from `expires`; no annotation means permanent.
	want := map[string]time.Duration{"192.0.2.10": 4*time.Minute + 3*time.Second, "198.51.100.0/24": 0}
	if len(els) != len(want) {
		t.Fatalf("got %v, want the %d elements %v", els, len(want), want)
	}
	for _, el := range els {
		ttl, ok := want[el.ip]
		if !ok {
			t.Errorf("unexpected element %q in %v", el.ip, els)
			continue
		}
		if el.ttl != ttl {
			t.Errorf("element %q ttl = %v, want %v", el.ip, el.ttl, ttl)
		}
	}
}
