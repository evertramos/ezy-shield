package store

// Per-IP read queries backing the daemon's "report" verb (issue #54).
// Everything here is read-only; the append-only invariant on audit_log and
// all write paths are untouched. All SQL uses parameterized queries; the IP
// is never interpolated into query strings (Hard Rule §4).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// reportLimitCap bounds every list-shaped report query so a single call
// cannot balloon process memory (same bound as ListAuditLog).
const reportLimitCap = 1000

// clampReportLimit normalises a caller-supplied row limit to [1, reportLimitCap].
func clampReportLimit(limit int) int {
	switch {
	case limit <= 0:
		return 1
	case limit > reportLimitCap:
		return reportLimitCap
	}
	return limit
}

// OffenderRecord mirrors one row of the offenders table. Timestamps are
// RFC 3339 UTC strings as stored.
type OffenderRecord struct {
	IP           string
	FirstSeen    string
	LastSeen     string
	TotalStrikes int
}

// GetOffender returns the offenders row for ip, or nil (not an error) when
// the IP has never been seen.
func (s *DB) GetOffender(ctx context.Context, ip netip.Addr) (*OffenderRecord, error) {
	var o OffenderRecord
	err := s.db.QueryRowContext(ctx, `
		SELECT ip, first_seen, last_seen, total_strikes
		FROM offenders WHERE ip = ?
	`, ip.String()).Scan(&o.IP, &o.FirstSeen, &o.LastSeen, &o.TotalStrikes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: GetOffender %s: %w", ip, err)
	}
	return &o, nil
}

// StrikeRecord mirrors one row of the strikes table with its verdicts
// decoded. RecordedAt is an RFC 3339 UTC string as stored; TTLSeconds is 0
// for permanent bans.
type StrikeRecord struct {
	ID         int64
	RecordedAt string
	StrikeNum  int
	TTLSeconds int64
	Reason     string
	Verdicts   []sdk.Verdict
}

// StrikesForIP returns up to limit strikes for ip in reverse chronological
// order (newest first). The limit is clamped to [1, 1000]. A corrupt
// verdicts column fails loudly rather than silently dropping data.
func (s *DB) StrikesForIP(ctx context.Context, ip netip.Addr, limit int) ([]StrikeRecord, error) {
	limit = clampReportLimit(limit)
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, recorded_at, strike_num, ttl_seconds, reason, verdicts
		FROM strikes
		WHERE ip = ?
		ORDER BY id DESC
		LIMIT ?
	`, ip.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("store: StrikesForIP %s: %w", ip, err)
	}
	defer func() { _ = rows.Close() }()

	var out []StrikeRecord
	for rows.Next() {
		var (
			r            StrikeRecord
			verdictsJSON string
		)
		if err := rows.Scan(&r.ID, &r.RecordedAt, &r.StrikeNum, &r.TTLSeconds, &r.Reason, &verdictsJSON); err != nil {
			return nil, fmt.Errorf("store: StrikesForIP scan: %w", err)
		}
		if verdictsJSON != "" {
			if err := json.Unmarshal([]byte(verdictsJSON), &r.Verdicts); err != nil {
				return nil, fmt.Errorf("store: StrikesForIP verdicts for strike %d: %w", r.ID, err)
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AuditLogForIP returns up to limit audit_log rows whose ip column exactly
// matches ip, newest first. Rows recorded against a CIDR prefix (manual
// prefix ops) are not included — they target a range, not this address.
// Read-only; the append-only invariant on audit_log is preserved.
func (s *DB) AuditLogForIP(ctx context.Context, ip netip.Addr, limit int) ([]AuditEntry, error) {
	limit = clampReportLimit(limit)
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, recorded_at, op, ip, ttl_seconds, strike_num, reason
		FROM audit_log
		WHERE ip = ?
		ORDER BY id DESC
		LIMIT ?
	`, ip.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("store: AuditLogForIP %s: %w", ip, err)
	}
	defer func() { _ = rows.Close() }()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.RecordedAt, &e.Op, &e.IP, &e.TTLSeconds, &e.Strike, &e.Reason); err != nil {
			return nil, fmt.Errorf("store: AuditLogForIP scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// BanRecord mirrors one row of bans_active. ExpiresAt is empty for permanent
// bans (Permanent is then true). Timestamps are RFC 3339 UTC strings as stored.
type BanRecord struct {
	BannedAt  string
	ExpiresAt string
	Permanent bool
	StrikeNum int
	Reason    string
}

// ActiveBanForIP returns the bans_active row for ip, or nil (not an error)
// when the IP is not actively banned. Callers should rely on the daemon's
// expiry ticker for pruning; a stale not-yet-pruned row may be returned.
func (s *DB) ActiveBanForIP(ctx context.Context, ip netip.Addr) (*BanRecord, error) {
	var (
		b         BanRecord
		expiresAt sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT banned_at, expires_at, strike_num, reason
		FROM bans_active WHERE ip = ?
	`, ip.String()).Scan(&b.BannedAt, &expiresAt, &b.StrikeNum, &b.Reason)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: ActiveBanForIP %s: %w", ip, err)
	}
	if expiresAt.Valid {
		b.ExpiresAt = expiresAt.String
	} else {
		b.Permanent = true
	}
	return &b, nil
}

// OffenderSummary is one row of the offender listing used by the report
// verb's list mode: the offenders row joined with its active-ban state.
type OffenderSummary struct {
	OffenderRecord
	Banned    bool
	Permanent bool
}

// ListOffenders returns up to limit offenders ordered by last_seen descending
// (most recently active first). When permanentOnly is true, only offenders
// with a permanent active ban are returned. The limit is clamped to [1, 1000].
func (s *DB) ListOffenders(ctx context.Context, permanentOnly bool, limit int) ([]OffenderSummary, error) {
	limit = clampReportLimit(limit)
	permInt := 0
	if permanentOnly {
		permInt = 1
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.ip, o.first_seen, o.last_seen, o.total_strikes,
		       b.ip IS NOT NULL,
		       b.ip IS NOT NULL AND b.expires_at IS NULL
		FROM offenders o
		LEFT JOIN bans_active b ON b.ip = o.ip
		WHERE ? = 0 OR (b.ip IS NOT NULL AND b.expires_at IS NULL)
		ORDER BY o.last_seen DESC, o.ip
		LIMIT ?
	`, permInt, limit)
	if err != nil {
		return nil, fmt.Errorf("store: ListOffenders: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []OffenderSummary
	for rows.Next() {
		var o OffenderSummary
		if err := rows.Scan(&o.IP, &o.FirstSeen, &o.LastSeen, &o.TotalStrikes, &o.Banned, &o.Permanent); err != nil {
			return nil, fmt.Errorf("store: ListOffenders scan: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
