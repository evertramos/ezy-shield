package ownership

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// TestChownToGroup_UnknownGroup verifies the helper surfaces an error (which the
// caller logs) instead of silently succeeding when the ezyshield group is absent
// — e.g. a container where 'ezyshield init' never ran.
func TestChownToGroup_UnknownGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ChownToGroup(path, "no-such-group-ezyshield-xyz"); err == nil {
		t.Fatal("expected error for unknown group, got nil")
	}
}

// TestChownToGroup_SetsGroupNotOwner verifies the socket's group is set while
// the owner is left untouched. Leaving the owner alone is what lets the helper
// run without CAP_CHOWN (issue #6); forcing the owner to root would fail with
// EPERM when this test runs as a non-root user, so this also guards against
// regressing back to an owner-forcing chown.
func TestChownToGroup_SetsGroupNotOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	uidBefore := before.Sys().(*syscall.Stat_t).Uid

	// The current process's primary group always exists and we are a member, so
	// chowning to it needs no privilege — exercises the happy path.
	gid := os.Getgid()
	g, err := user.LookupGroupId(strconv.Itoa(gid))
	if err != nil {
		t.Skipf("cannot resolve current gid %d to a group name: %v", gid, err)
	}

	if err := ChownToGroup(path, g.Name); err != nil {
		t.Fatalf("ChownToGroup: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if int(st.Gid) != gid {
		t.Errorf("group = %d, want %d", st.Gid, gid)
	}
	if st.Uid != uidBefore {
		t.Errorf("owner changed to %d, want unchanged %d", st.Uid, uidBefore)
	}
}
