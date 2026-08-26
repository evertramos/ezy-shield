// SPDX-License-Identifier: AGPL-3.0-only

package store

// UnbanAll backs the panic button (`ezyshield disable --all`, issue #176):
// it clears every bans_active row — real, simulated, and manual — in one
// transaction, leaving offender history, strikes, and the audit trail fully
// intact (this is an enforcement reset, not a data wipe). The caller (the
// daemon's disable_all verb) reconciles the enforcers afterwards, so the
// now-empty desired state empties the local set and the edge lists via
// their normal reconcile paths.

import (
	"context"
	"fmt"
)

// UnbanAll removes every active ban and appends ONE summary audit entry
// (op "disable_all") naming the count — per-IP unban entries would flood
// the journal in exactly the emergency this exists for. Returns the number
// of bans removed.
func (s *DB) UnbanAll(ctx context.Context, reason string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin UnbanAll: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `DELETE FROM bans_active`)
	if err != nil {
		return 0, fmt.Errorf("store: UnbanAll delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: UnbanAll rows affected: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_log (recorded_at, op, ip, ttl_seconds, strike_num, reason)
		VALUES (?, 'disable_all', '-', 0, 0, ?)
	`, nowRFC3339(), fmt.Sprintf("%s (removed %d active bans)", reason, n)); err != nil {
		return 0, fmt.Errorf("store: UnbanAll audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit UnbanAll: %w", err)
	}
	return int(n), nil
}
