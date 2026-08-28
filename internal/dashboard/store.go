// SPDX-License-Identifier: AGPL-3.0-only

package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	// modernc.org/sqlite is already a repo-level dependency (see internal/store);
	// no new external dependency is introduced by importing the driver here.
	_ "modernc.org/sqlite"
)

// authStore is a small SQLite-backed store dedicated to the dashboard.
// It is intentionally separate from internal/store so that dashboard schema
// evolution does not require touching the daemon's append-only migration
// series (docs/ARCHITECTURE.md §6). The file is created with mode 0600.
type authStore struct {
	db *sql.DB
}

const authSchema = `
CREATE TABLE IF NOT EXISTS dashboard_admin (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at    INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS rbac_denials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    held_role   TEXT NOT NULL
);`

func openAuthStore(path string) (*authStore, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	// Same pragma baseline as the daemon's main store (internal/store):
	// WAL journal, 5 s busy retry, synchronous=NORMAL. The _pragma=name(value)
	// form is the modernc.org/sqlite driver's syntax; mattn-style parameters
	// are silently ignored by this driver (issues #321/#406). Before #406 this
	// DSN had no pragmas at all: delete journal, busy_timeout=0, unbounded pool.
	// TestOpenAuthStore_AppliesPragmasAndPoolCap pins the effective values.
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)" //nolint:gosec // path is the admin-controlled dashboard auth DB location
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// SQLite allows only one concurrent writer; funnel all dashboard requests
	// through a single connection like the main store does.
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(context.Background(), authSchema); err != nil {
		_ = db.Close() //nolint:errcheck // best-effort close on failed open
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	// Tighten the file mode after creation. sql.Open goes through the
	// driver's own path, which does not honour a restrictive umask on all
	// platforms; chmod after schema apply is portable. In WAL mode the
	// -wal/-shm sidecars are created by the schema apply above (i.e. before
	// this chmod) and later carry password-hash pages, so tighten them too.
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = db.Close() //nolint:errcheck // best-effort close on failed chmod
			return nil, fmt.Errorf("chmod %s: %w", p, err)
		}
	}
	return &authStore{db: db}, nil
}

func (s *authStore) hasAdmin(ctx context.Context) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dashboard_admin`).Scan(&n); err != nil {
		return false, fmt.Errorf("count admins: %w", err)
	}
	return n > 0, nil
}

func (s *authStore) setAdmin(ctx context.Context, username, hash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO dashboard_admin (username, password_hash) VALUES (?, ?)
		 ON CONFLICT(username) DO UPDATE
		     SET password_hash = excluded.password_hash,
		         updated_at    = strftime('%s','now')`,
		username, hash)
	if err != nil {
		return fmt.Errorf("set admin: %w", err)
	}
	return nil
}

func (s *authStore) getAdminHash(ctx context.Context, username string) (string, error) {
	var h string
	err := s.db.QueryRowContext(ctx,
		`SELECT password_hash FROM dashboard_admin WHERE username = ?`, username).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errAdminNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get admin hash: %w", err)
	}
	return h, nil
}

// auditRBACDenial appends one 403 record (issue #204): who tried what with
// which role. Actor and action only — tokens never reach this table.
func (s *authStore) auditRBACDenial(ctx context.Context, actor, action, heldRole string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rbac_denials (actor, action, held_role) VALUES (?, ?, ?)`,
		actor, action, heldRole)
	if err != nil {
		return fmt.Errorf("insert rbac denial: %w", err)
	}
	return nil
}

// rbacDenial is one audited 403 row.
type rbacDenial struct {
	Actor    string
	Action   string
	HeldRole string
}

// listRBACDenials returns the most recent denials, newest first.
func (s *authStore) listRBACDenials(ctx context.Context, limit int) ([]rbacDenial, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT actor, action, held_role FROM rbac_denials ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list rbac denials: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	var out []rbacDenial
	for rows.Next() {
		var d rbacDenial
		if err := rows.Scan(&d.Actor, &d.Action, &d.HeldRole); err != nil {
			return nil, fmt.Errorf("scan rbac denial: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *authStore) close() error {
	return s.db.Close()
}
