// Package store provides the SQLite persistence layer for EzyShield.
//
// All SQL uses parameterized queries; log-derived data is never interpolated
// into query strings (Hard Rule §4 from AGENTS.md).
// The audit_log table has no UPDATE or DELETE code paths by construction.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // register "sqlite" driver

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DB is the EzyShield SQLite store. It is safe for concurrent use; WAL mode
// allows multiple simultaneous readers while a single writer serialises writes.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path, enables WAL mode, and
// applies any pending migrations. Call Close when done.
func Open(ctx context.Context, path string) (*DB, error) {
	// _journal=WAL: concurrent readers don't block writers.
	// _busy_timeout=5000: retry for up to 5 s on SQLITE_BUSY instead of erroring.
	// _synchronous=NORMAL: safe with WAL (no risk of corruption).
	dsn := "file:" + path + "?_journal=WAL&_busy_timeout=5000&_synchronous=NORMAL" //nolint:gosec // path is the admin-controlled database location from config
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}

	// SQLite allows only one concurrent writer; avoid "database is locked" errors
	// by funnelling all writes through a single connection.
	sqlDB.SetMaxOpenConns(1)

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	s := &DB{db: sqlDB}
	if err := s.migrate(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}

	return s, nil
}

// Close releases the underlying database connection.
func (s *DB) Close() error {
	return s.db.Close()
}

// migrate bootstraps schema_migrations and applies every pending *.sql file
// in the embedded migrations directory in version order.
func (s *DB) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT    NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("bootstrap schema_migrations: %w", err)
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("reading migrations dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version, err := parseMigrationVersion(e.Name())
		if err != nil {
			return err
		}

		var dummy int
		scanErr := s.db.QueryRowContext(ctx,
			`SELECT 1 FROM schema_migrations WHERE version = ?`, version).Scan(&dummy)
		if scanErr == nil {
			continue // already applied
		}
		if scanErr != sql.ErrNoRows {
			return fmt.Errorf("checking migration %d: %w", version, scanErr)
		}

		sqlBytes, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", e.Name(), err)
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("exec migration %d: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			version, nowRFC3339()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
	}

	return nil
}

// parseMigrationVersion extracts the numeric prefix from a migration file name
// such as "001_initial.sql" → 1.
func parseMigrationVersion(name string) (int, error) {
	parts := strings.SplitN(name, "_", 2)
	if len(parts) == 0 {
		return 0, fmt.Errorf("invalid migration filename: %s", name)
	}
	v, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("migration version in %s: %w", name, err)
	}
	return v, nil
}

// RecordStrike records a new strike for the IP in a, upserts the offender row
// (preserving first_seen), inserts a ban into bans_active, and appends an
// audit entry — all in one transaction.
func (s *DB) RecordStrike(ctx context.Context, a sdk.Action) error {
	ip := a.IP.String()
	now := nowRFC3339()
	ttlSec := int64(a.TTL.Seconds())

	verdictsJSON, err := json.Marshal(a.Verdicts)
	if err != nil {
		return fmt.Errorf("store: marshal verdicts: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin RecordStrike: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Upsert offender: first_seen only on INSERT; last_seen + total_strikes always bumped.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO offenders (ip, first_seen, last_seen, total_strikes)
		VALUES (?, ?, ?, 1)
		ON CONFLICT(ip) DO UPDATE SET
			last_seen     = excluded.last_seen,
			total_strikes = total_strikes + 1
	`, ip, now, now); err != nil {
		return fmt.Errorf("store: upsert offender: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO strikes (ip, recorded_at, strike_num, ttl_seconds, reason, verdicts)
		VALUES (?, ?, ?, ?, ?, ?)
	`, ip, now, a.Strike, ttlSec, a.Reason, string(verdictsJSON)); err != nil {
		return fmt.Errorf("store: insert strike: %w", err)
	}

	// expires_at is NULL for permanent bans (TTL == 0).
	var expiresAt *string
	if a.TTL > 0 {
		t := time.Now().UTC().Add(a.TTL).Format(time.RFC3339Nano)
		expiresAt = &t
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO bans_active (ip, banned_at, expires_at, strike_num, reason)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			banned_at  = excluded.banned_at,
			expires_at = excluded.expires_at,
			strike_num = excluded.strike_num,
			reason     = excluded.reason
	`, ip, now, expiresAt, a.Strike, a.Reason); err != nil {
		return fmt.Errorf("store: upsert ban: %w", err)
	}

	// Append audit entry — this table has NO UPDATE/DELETE paths.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_log (recorded_at, op, ip, ttl_seconds, strike_num, reason)
		VALUES (?, ?, ?, ?, ?, ?)
	`, now, a.Op, ip, ttlSec, a.Strike, a.Reason); err != nil {
		return fmt.Errorf("store: insert audit: %w", err)
	}

	return tx.Commit()
}

// GetStrikeCount returns the total cumulative strike count for ip.
// Returns 0 (not an error) if the IP has never been seen.
func (s *DB) GetStrikeCount(ctx context.Context, ip netip.Addr) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT total_strikes FROM offenders WHERE ip = ?`, ip.String()).Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: GetStrikeCount %s: %w", ip, err)
	}
	return count, nil
}

// ActiveBans returns all bans currently in bans_active (including permanent ones).
// Callers should call ExpireBans first to flush stale entries.
func (s *DB) ActiveBans(ctx context.Context) ([]sdk.Action, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ip, banned_at, expires_at, strike_num, reason FROM bans_active
	`)
	if err != nil {
		return nil, fmt.Errorf("store: ActiveBans: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []sdk.Action
	for rows.Next() {
		var (
			ipStr     string
			bannedAt  string // kept in SELECT for audit/debug; unused in TTL calc
			expiresAt sql.NullString
			strikeNum int
			reason    string
		)
		if err := rows.Scan(&ipStr, &bannedAt, &expiresAt, &strikeNum, &reason); err != nil {
			return nil, fmt.Errorf("store: ActiveBans scan: %w", err)
		}

		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return nil, fmt.Errorf("store: ActiveBans bad IP %q: %w", ipStr, err)
		}

		var ttl time.Duration
		if expiresAt.Valid {
			et, err := time.Parse(time.RFC3339Nano, expiresAt.String)
			if err != nil {
				return nil, fmt.Errorf("store: parse expires_at: %w", err)
			}
			remaining := time.Until(et)
			if remaining < 0 {
				remaining = 0
			}
			ttl = remaining
		}

		out = append(out, sdk.Action{
			IP:     ip,
			Op:     "ban",
			TTL:    ttl,
			Strike: strikeNum,
			Reason: reason,
		})
	}
	return out, rows.Err()
}

// ExpireBans removes bans whose expires_at is before now from bans_active.
// Returns the number of rows removed. Writes an audit entry for each expired ban.
func (s *DB) ExpireBans(ctx context.Context, now time.Time) (int, error) {
	nowStr := now.UTC().Format(time.RFC3339Nano)

	// Audit expired bans before deleting them.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (recorded_at, op, ip, ttl_seconds, strike_num, reason)
		SELECT ?, 'expire', ip, 0, strike_num, 'ttl expired'
		FROM bans_active
		WHERE expires_at IS NOT NULL AND expires_at < ?
	`, nowStr, nowStr)
	if err != nil {
		return 0, fmt.Errorf("store: ExpireBans audit: %w", err)
	}

	res, err := s.db.ExecContext(ctx, `
		DELETE FROM bans_active WHERE expires_at IS NOT NULL AND expires_at < ?
	`, nowStr)
	if err != nil {
		return 0, fmt.Errorf("store: ExpireBans: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Unban removes ip from bans_active and appends an audit entry.
// It is idempotent: if ip is not in bans_active it still audits and returns nil.
func (s *DB) Unban(ctx context.Context, ip netip.Addr) error {
	now := nowRFC3339()
	ipStr := ip.String()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin Unban: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM bans_active WHERE ip = ?`, ipStr); err != nil {
		return fmt.Errorf("store: Unban delete: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_log (recorded_at, op, ip, ttl_seconds, strike_num, reason)
		VALUES (?, 'unban', ?, 0, 0, 'manual unban')
	`, now, ipStr); err != nil {
		return fmt.Errorf("store: Unban audit: %w", err)
	}

	return tx.Commit()
}

// Audit appends an audit entry for a. Use this for actions (e.g. "unban",
// "notify_only") that don't go through RecordStrike.
// This is the ONLY function allowed to write to audit_log; there are no
// UPDATE or DELETE paths for that table.
func (s *DB) Audit(ctx context.Context, a sdk.Action) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (recorded_at, op, ip, ttl_seconds, strike_num, reason)
		VALUES (?, ?, ?, ?, ?, ?)
	`, nowRFC3339(), a.Op, a.IP.String(), int64(a.TTL.Seconds()), a.Strike, a.Reason)
	if err != nil {
		return fmt.Errorf("store: Audit: %w", err)
	}
	return nil
}

// RecordUsage inserts a row into ai_usage for a single AI provider call.
// cost_usd is derived by the caller from token counts and provider pricing.
func (s *DB) RecordUsage(ctx context.Context, provider string, usage sdk.Usage) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ai_usage (called_at, provider, input_tokens, output_tokens, cost_usd)
		VALUES (?, ?, ?, ?, ?)
	`, nowRFC3339(), provider, usage.InputTokens, usage.OutputTokens, usage.CostUSD)
	if err != nil {
		return fmt.Errorf("store: RecordUsage: %w", err)
	}
	return nil
}

// TodayUsage returns the sum of input_tokens, output_tokens, and cost_usd
// recorded in ai_usage for provider since UTC midnight today.
func (s *DB) TodayUsage(ctx context.Context, provider string) (sdk.Usage, error) {
	today := time.Now().UTC().Format("2006-01-02")
	var u sdk.Usage
	err := s.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(input_tokens), 0),
			COALESCE(SUM(output_tokens), 0),
			COALESCE(SUM(cost_usd), 0)
		FROM ai_usage
		WHERE provider = ?
		  AND called_at >= ?
	`, provider, today).Scan(&u.InputTokens, &u.OutputTokens, &u.CostUSD)
	if err != nil {
		return sdk.Usage{}, fmt.Errorf("store: TodayUsage: %w", err)
	}
	return u, nil
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
