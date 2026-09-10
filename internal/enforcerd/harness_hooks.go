// SPDX-License-Identifier: AGPL-3.0-only

package enforcerd

// harness_hooks.go — exported seams for the integration harness (issue
// #605). Production wiring (cmd/ezyshield-enforcer/main.go) never calls
// them; they exist so internal/e2e can run this real server against a
// scripted kernel (internal/enforcerd/nfttest) on a virtual clock instead
// of re-modelling the cache in a fake.

import (
	"context"
	"time"
)

// SetClock replaces the clock behind cache-expiry decisions. nil restores
// time.Now.
func (s *Server) SetClock(now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	s.nowFn = now
}

// SetSessionKiller replaces the pre-ban TCP teardown (`ss -K`). The harness
// installs a no-op: there are no real sockets to tear down.
func (s *Server) SetSessionKiller(fn func(ctx context.Context, args []string) error) {
	s.runSs = fn
}

// SetListSetOutput replaces how `nft list set` output is obtained — the
// scripted kernel renders it — and returns a function that restores the
// real command. Package-wide: harness tests must not run in parallel.
func SetListSetOutput(fn func(ctx context.Context, family, table, set string) ([]byte, error)) (restore func()) {
	prev := listSetOutput
	listSetOutput = fn
	return func() { listSetOutput = prev }
}
