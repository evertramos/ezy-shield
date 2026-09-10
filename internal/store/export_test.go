// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"net/netip"
)

// LastSuppressedAtForTest reads bans_active.last_suppressed_at (issue #587)
// for the external test package; valid=false means NULL.
func (s *DB) LastSuppressedAtForTest(ctx context.Context, ip netip.Addr) (string, bool, error) {
	var v sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT last_suppressed_at FROM bans_active WHERE ip = ?`, ip.String()).Scan(&v)
	return v.String, v.Valid, err
}
