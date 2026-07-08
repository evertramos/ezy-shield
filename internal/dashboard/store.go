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
);`

func openAuthStore(path string) (*authStore, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(authSchema); err != nil {
		_ = db.Close() //nolint:errcheck // best-effort close on failed open
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	// Tighten the file mode after creation. sql.Open goes through the
	// driver's own path, which does not honour a restrictive umask on all
	// platforms; chmod after schema apply is portable.
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = db.Close() //nolint:errcheck // best-effort close on failed chmod
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}
	return &authStore{db: db}, nil
}

func (s *authStore) HasAdmin(ctx context.Context) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dashboard_admin`).Scan(&n); err != nil {
		return false, fmt.Errorf("count admins: %w", err)
	}
	return n > 0, nil
}

func (s *authStore) SetAdmin(ctx context.Context, username, hash string) error {
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

func (s *authStore) GetAdminHash(ctx context.Context, username string) (string, error) {
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

func (s *authStore) Close() error {
	return s.db.Close()
}
