// SPDX-License-Identifier: AGPL-3.0-only

package store

// Internal-package test: reaches the unexported db handle to verify the PRAGMAs
// the DSN promises are actually in effect on the pooled connection.

import (
	"context"
	"path/filepath"
	"testing"
)

// TestOpen_AppliesPragmas reproduces issue #321: the DSN used mattn/go-sqlite3
// parameter syntax (_journal, _busy_timeout, _synchronous), which the
// modernc.org/sqlite driver silently ignores — leaving journal_mode=delete,
// busy_timeout=0, and synchronous=FULL despite the comments (and the
// cross-process daemon+scan usage) relying on WAL and the 5 s busy retry.
func TestOpen_AppliesPragmas(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "pragma.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

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
}
