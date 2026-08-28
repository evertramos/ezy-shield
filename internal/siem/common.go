// SPDX-License-Identifier: AGPL-3.0-only

package siem

import "time"

// rfc3339UTC renders t as an RFC 3339 timestamp in UTC, or "" when t is the
// zero value. All three formatters share this so a zero Event.Time maps to
// each format's documented null representation rather than the misleading
// "0001-01-01T00:00:00Z".
func rfc3339UTC(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
