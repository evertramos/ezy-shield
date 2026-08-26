// SPDX-License-Identifier: AGPL-3.0-only

package store

// Persistent per-IP hourly event counters (issue #134) — the storage half of
// low-and-slow detection. Long-window (>1h) rules cannot ride the in-memory
// aggregator (RAM cost, LRU eviction, restarts — the exact failure modes a
// slow attacker exploits), so the daemon keeps aggregate integers here: one
// row per (ip, kind, UTC hour), incremented in place. The table stores ONLY
// counts — no usernames, paths, or raw log lines — and is pruned once rows
// age past the longest long-window rule.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// HourBucket floors t to its UTC hour, as epoch seconds — the bucket_start
// key of events_agg.
func HourBucket(t time.Time) int64 {
	return t.UTC().Truncate(time.Hour).Unix()
}

// IncrEventCount adds 1 to the (ip, kind, bucketStart) counter, creating the
// row on first sight. kind is an internal enum (parser-defined), never raw
// log content.
func (s *DB) IncrEventCount(ctx context.Context, ip netip.Addr, kind string, bucketStart int64) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO events_agg (ip, kind, bucket_start, count)
		VALUES (?, ?, ?, 1)
		ON CONFLICT(ip, kind, bucket_start) DO UPDATE SET count = count + 1
	`, ip.String(), kind, bucketStart)
	if err != nil {
		return fmt.Errorf("store: IncrEventCount: %w", err)
	}
	return nil
}

// SumEventCounts returns, per kind, the summed counts for ip across buckets
// with bucket_start >= since (epoch seconds). Kinds with no rows are absent
// from the map. Buckets are hour-coarse, so a window boundary lands on the
// containing hour — long-window thresholds must tolerate that slack.
func (s *DB) SumEventCounts(ctx context.Context, ip netip.Addr, kinds []string, since int64) (map[string]int, error) {
	if len(kinds) == 0 {
		return map[string]int{}, nil
	}
	// Kinds are internal enum values from loaded rules, but still bound as
	// parameters (Hard Rule §4 — nothing is interpolated).
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",")
	args := make([]any, 0, len(kinds)+2)
	args = append(args, ip.String(), since)
	for _, k := range kinds {
		args = append(args, k)
	}
	// G202: the concatenated fragment is only "?,?,..." built from
	// len(kinds) — every value still binds as a parameter.
	query := "SELECT kind, SUM(count) FROM events_agg WHERE ip = ? AND bucket_start >= ? AND kind IN (" + placeholders + ") GROUP BY kind" //nolint:gosec // placeholder list only; all values parameterized
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: SumEventCounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]int, len(kinds))
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, fmt.Errorf("store: SumEventCounts scan: %w", err)
		}
		out[kind] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: SumEventCounts rows: %w", err)
	}
	return out, nil
}

// PruneEventCounts deletes buckets with bucket_start < before (epoch
// seconds), returning the number of rows removed. The daemon runs this on
// its existing flush ticker with before = now - longest long window, so the
// table can never grow unbounded.
func (s *DB) PruneEventCounts(ctx context.Context, before int64) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM events_agg WHERE bucket_start < ?`, before)
	if err != nil {
		return 0, fmt.Errorf("store: PruneEventCounts: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: PruneEventCounts rows affected: %w", err)
	}
	return int(n), nil
}
