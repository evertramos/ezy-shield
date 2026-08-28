// SPDX-License-Identifier: AGPL-3.0-only

package store

// Read-only events_agg queries for `ezyshield rule test` (issue #224).
// The dry evaluation must have zero side effects, so this file contains
// SELECTs only — no INSERT/UPDATE/DELETE may ever be added here.

import (
	"context"
	"fmt"
	"strings"
)

// HourCount is one (ip, UTC-hour) aggregate: the summed event count across
// the queried kinds. Counts only — the table never stores field values or
// raw log content.
type HourCount struct {
	IP          string
	BucketStart int64 // epoch seconds, floored to the UTC hour
	Count       int
}

// EventCountsByHour returns, for every IP with activity, the per-hour summed
// counts across kinds for buckets with bucket_start >= since (epoch
// seconds), ordered by (ip, bucket_start) so callers can slide windows in a
// single pass. Kinds are internal enum values from validated rules, but are
// still bound as parameters (Hard Rule §4).
func (s *DB) EventCountsByHour(ctx context.Context, kinds []string, since int64) ([]HourCount, error) {
	if len(kinds) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",")
	args := make([]any, 0, len(kinds)+1)
	args = append(args, since)
	for _, k := range kinds {
		args = append(args, k)
	}
	// G202: the concatenated fragment is only "?,?,..." — every value binds
	// as a parameter.
	query := "SELECT ip, bucket_start, SUM(count) FROM events_agg WHERE bucket_start >= ? AND kind IN (" + placeholders + ") GROUP BY ip, bucket_start ORDER BY ip, bucket_start" //nolint:gosec // placeholder list only; all values parameterized
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: EventCountsByHour: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []HourCount
	for rows.Next() {
		var hc HourCount
		if err := rows.Scan(&hc.IP, &hc.BucketStart, &hc.Count); err != nil {
			return nil, fmt.Errorf("store: EventCountsByHour scan: %w", err)
		}
		out = append(out, hc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: EventCountsByHour rows: %w", err)
	}
	return out, nil
}
