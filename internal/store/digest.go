// SPDX-License-Identifier: AGPL-3.0-only

package store

// Window-scoped read queries backing `ezyshield report --since` (issue
// #229): the incident digest. Everything here is SELECT-only — the digest
// must have zero side effects, so no INSERT/UPDATE/DELETE may ever be
// added to this file.
//
// Timestamp filtering note: recorded_at/scored_at are RFC3339Nano TEXT and
// RFC3339Nano trims trailing zeros, which makes lexicographic comparison
// unreliable only WITHIN the boundary second (see LastStrike's id-ordering
// comment). For a digest window that sub-second slack is immaterial, so
// the queries compare against a whole-second RFC3339 string.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// digestSinceKey formats t for comparison against stored RFC3339Nano
// timestamps: whole-second precision, UTC.
func digestSinceKey(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// WindowStrike is one strike inside the digest window, with its persisted
// verdicts decoded. Reason and verdict fields are hostile-log-derived —
// render-time sanitizing only.
type WindowStrike struct {
	IP        string
	StrikeNum int
	Reason    string
	Verdicts  []sdk.Verdict
}

// StrikesSince returns up to limit most-recent strikes recorded at or after
// since, plus the TOTAL window count (so callers can say "based on the most
// recent N of M" honestly when the detail set is truncated). Rows with
// undecodable verdicts JSON degrade to an empty verdict list, never an
// error — old rows must not break the digest.
func (s *DB) StrikesSince(ctx context.Context, since time.Time, limit int) ([]WindowStrike, int, error) {
	key := digestSinceKey(since)
	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM strikes WHERE recorded_at >= ?`, key).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: StrikesSince count: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT ip, strike_num, reason, verdicts
		FROM strikes
		WHERE recorded_at >= ?
		ORDER BY id DESC
		LIMIT ?
	`, key, clampDigestLimit(limit))
	if err != nil {
		return nil, 0, fmt.Errorf("store: StrikesSince: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []WindowStrike
	for rows.Next() {
		var ws WindowStrike
		var verdictsJSON string
		if err := rows.Scan(&ws.IP, &ws.StrikeNum, &ws.Reason, &verdictsJSON); err != nil {
			return nil, 0, fmt.Errorf("store: StrikesSince scan: %w", err)
		}
		_ = json.Unmarshal([]byte(verdictsJSON), &ws.Verdicts)
		out = append(out, ws)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: StrikesSince rows: %w", err)
	}
	return out, total, nil
}

// digestStrikeCap bounds the detail rows a digest ever loads; the window
// total is still exact.
const digestStrikeCap = 5000

func clampDigestLimit(limit int) int {
	if limit <= 0 || limit > digestStrikeCap {
		return digestStrikeCap
	}
	return limit
}

// AuditOpCountsSince returns, per audit op ("ban", "dry_ban", "unban", …),
// the number of audit_log entries recorded at or after since.
func (s *DB) AuditOpCountsSince(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT op, COUNT(*)
		FROM audit_log
		WHERE recorded_at >= ?
		GROUP BY op
	`, digestSinceKey(since))
	if err != nil {
		return nil, fmt.Errorf("store: AuditOpCountsSince: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]int{}
	for rows.Next() {
		var op string
		var n int
		if err := rows.Scan(&op, &n); err != nil {
			return nil, fmt.Errorf("store: AuditOpCountsSince scan: %w", err)
		}
		out[op] = n
	}
	return out, rows.Err()
}

// EventKindTotalsSince returns, per kind, the summed events_agg counts for
// buckets with bucket_start >= since (epoch seconds), plus the number of
// distinct IPs with any activity in the window.
func (s *DB) EventKindTotalsSince(ctx context.Context, since int64) (map[string]int, int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT kind, SUM(count)
		FROM events_agg
		WHERE bucket_start >= ?
		GROUP BY kind
	`, since)
	if err != nil {
		return nil, 0, fmt.Errorf("store: EventKindTotalsSince: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]int{}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, 0, fmt.Errorf("store: EventKindTotalsSince scan: %w", err)
		}
		out[kind] = n
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: EventKindTotalsSince rows: %w", err)
	}

	var ips int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ip) FROM events_agg WHERE bucket_start >= ?`, since).Scan(&ips); err != nil {
		return nil, 0, fmt.Errorf("store: EventKindTotalsSince ips: %w", err)
	}
	return out, ips, nil
}

// OffenderMeta is the offenders-table view the digest needs to split new
// vs repeat offenders.
type OffenderMeta struct {
	FirstSeen    string
	TotalStrikes int
}

// OffenderMetaFor returns first_seen/total_strikes for each of the given
// IPs (absent rows are simply missing from the map). The IN list is bound
// entirely as parameters (Hard Rule §4); callers pass the bounded distinct
// IP set of a strike window, capped defensively here as well.
func (s *DB) OffenderMetaFor(ctx context.Context, ips []string) (map[string]OffenderMeta, error) {
	out := map[string]OffenderMeta{}
	if len(ips) == 0 {
		return out, nil
	}
	if len(ips) > digestStrikeCap {
		ips = ips[:digestStrikeCap]
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ips)), ",")
	args := make([]any, len(ips))
	for i, ip := range ips {
		args[i] = ip
	}
	// G202: the concatenated fragment is only "?,?,..." — every value binds
	// as a parameter.
	query := "SELECT ip, first_seen, total_strikes FROM offenders WHERE ip IN (" + placeholders + ")" //nolint:gosec // placeholder list only; all values parameterized
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: OffenderMetaFor: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var ip string
		var m OffenderMeta
		if err := rows.Scan(&ip, &m.FirstSeen, &m.TotalStrikes); err != nil {
			return nil, fmt.Errorf("store: OffenderMetaFor scan: %w", err)
		}
		out[ip] = m
	}
	return out, rows.Err()
}

// ActiveBanSummary returns counts over bans_active: total rows, permanent
// (NULL expires_at), and dry-run rows.
func (s *DB) ActiveBanSummary(ctx context.Context) (total, permanent, dry int, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN expires_at IS NULL THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN dry_run = 1 THEN 1 ELSE 0 END), 0)
		FROM bans_active
	`).Scan(&total, &permanent, &dry)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("store: ActiveBanSummary: %w", err)
	}
	return total, permanent, dry, nil
}
