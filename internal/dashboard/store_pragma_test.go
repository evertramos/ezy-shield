// SPDX-License-Identifier: AGPL-3.0-only

package dashboard

// Internal-package test: reaches the unexported db handle to verify the
// PRAGMAs the auth-store DSN promises are actually in effect on the pooled
// connection — mirroring internal/store/pragma_test.go (issue #321).
//
// Issue #406: before the fix, openAuthStore opened the SQLite file with no
// pragmas and no pool cap at all — delete journal, busy_timeout=0, and an
// unbounded connection pool, weaker than the main store's baseline.

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenAuthStore_AppliesPragmasAndPoolCap(t *testing.T) {
	ctx := context.Background()
	s, err := openAuthStore(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("openAuthStore: %v", err)
	}
	defer func() { _ = s.close() }()

	var journalMode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want %q", journalMode, "wal")
	}

	var busyTimeout int
	if err := s.db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", busyTimeout)
	}

	// synchronous: 0=OFF 1=NORMAL 2=FULL 3=EXTRA
	var synchronous int
	if err := s.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatalf("PRAGMA synchronous: %v", err)
	}
	if synchronous != 1 {
		t.Errorf("synchronous = %d, want 1 (NORMAL)", synchronous)
	}

	// SQLite allows a single writer; the pool must be capped like the main
	// store's (Stats reports 0 for an unbounded pool).
	if got := s.db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1", got)
	}
}

// TestOpenAuthStore_TightensSidecarPerms: in WAL mode the -wal/-shm sidecar
// files are created by the schema apply (before the post-create chmod) and
// later carry password-hash pages, so they must end up 0600 like the DB file.
func TestOpenAuthStore_TightensSidecarPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := openAuthStore(path)
	if err != nil {
		t.Fatalf("openAuthStore: %v", err)
	}
	defer func() { _ = s.close() }()

	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue // sidecars may be absent (e.g. already checkpointed)
		}
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := info.Mode().Perm(); perm != fs.FileMode(0o600) {
			t.Errorf("%s mode = %o, want 0600", filepath.Base(p), perm)
		}
	}
}
