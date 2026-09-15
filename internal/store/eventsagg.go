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
	// Watermarks recorded before the prune horizon cover only pruned
	// buckets: drop them too (issue #636).
	if _, err := s.db.ExecContext(ctx, `DELETE FROM events_consumed WHERE recorded_at < ?`, before); err != nil {
		return 0, fmt.Errorf("store: PruneEventCounts consumed: %w", err)
	}
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

// ConsumeEventCounts records, for each long window, the counts ip has
// accumulated in that window at now — the evidence the strike being
// recorded consumed (issue #636). SumEventCounts callers subtract these
// through ConsumedEventCounts, so the next rung needs threshold NEW events.
// windows maps a rule window to the counter kinds its rules read.
func (s *DB) ConsumeEventCounts(ctx context.Context, ip netip.Addr, windows map[time.Duration][]string, now time.Time) error {
	// Read every window's sums BEFORE opening the write transaction: the
	// pool hands out one connection, and a read issued while the
	// transaction holds it would wait on itself.
	snapshot := make(map[time.Duration]map[string]int, len(windows))
	for w, kinds := range windows {
		sums, err := s.SumEventCounts(ctx, ip, kinds, HourBucket(now.Add(-w)))
		if err != nil {
			return err
		}
		snapshot[w] = sums
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: ConsumeEventCounts begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for w, kinds := range windows {
		sums := snapshot[w]
		for _, k := range kinds {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO events_consumed (ip, window_s, kind, consumed, recorded_at)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(ip, window_s, kind) DO UPDATE SET consumed = excluded.consumed, recorded_at = excluded.recorded_at
			`, ip.String(), int64(w/time.Second), k, sums[k], now.Unix()); err != nil {
				return fmt.Errorf("store: ConsumeEventCounts: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: ConsumeEventCounts commit: %w", err)
	}
	return nil
}

// ConsumedEventCounts returns the per-kind counts consumed by ip's last
// strike for window, ignoring a watermark older than the window itself
// (every event it covered has aged out). Absent kinds map to 0.
func (s *DB) ConsumedEventCounts(ctx context.Context, ip netip.Addr, window time.Duration, now time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT kind, consumed FROM events_consumed
		WHERE ip = ? AND window_s = ? AND recorded_at >= ?
	`, ip.String(), int64(window/time.Second), now.Add(-window).Unix())
	if err != nil {
		return nil, fmt.Errorf("store: ConsumedEventCounts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, fmt.Errorf("store: ConsumedEventCounts scan: %w", err)
		}
		out[kind] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: ConsumedEventCounts rows: %w", err)
	}
	return out, nil
}
