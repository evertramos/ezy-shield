package enforce

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// MultiEnforcer fans Ban/Unban/Sync out to multiple underlying enforcers.
// All enforcers are always called; individual failures are logged as warnings
// and combined into a single returned error.
type MultiEnforcer struct {
	enforcers []sdk.Enforcer
}

// NewMulti returns a MultiEnforcer wrapping the given enforcers in order.
func NewMulti(enforcers ...sdk.Enforcer) *MultiEnforcer {
	return &MultiEnforcer{enforcers: enforcers}
}

// Name returns a combined name like "nftables+cloudflare".
func (m *MultiEnforcer) Name() string {
	names := make([]string, len(m.enforcers))
	for i, e := range m.enforcers {
		names[i] = e.Name()
	}
	return strings.Join(names, "+")
}

// Ban calls Ban on every enforcer, logging individual failures.
func (m *MultiEnforcer) Ban(ctx context.Context, t sdk.Target) error {
	var errs []error
	for _, e := range m.enforcers {
		if err := e.Ban(ctx, t); err != nil {
			slog.WarnContext(ctx, "enforce/multi: Ban failed", "enforcer", e.Name(), "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Unban calls Unban on every enforcer.
func (m *MultiEnforcer) Unban(ctx context.Context, t sdk.Target) error {
	var errs []error
	for _, e := range m.enforcers {
		if err := e.Unban(ctx, t); err != nil {
			slog.WarnContext(ctx, "enforce/multi: Unban failed", "enforcer", e.Name(), "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Sync calls Sync on every enforcer.
func (m *MultiEnforcer) Sync(ctx context.Context, want []sdk.Target) error {
	var errs []error
	for _, e := range m.enforcers {
		if err := e.Sync(ctx, want); err != nil {
			slog.WarnContext(ctx, "enforce/multi: Sync failed", "enforcer", e.Name(), "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Allow forwards the allowlist addition to every enforcer that mirrors the
// allowlist locally (AllowlistSyncer); enforcers without the concept (edge
// blockers like Cloudflare) are skipped. Individual failures are logged and
// joined, matching Ban/Unban/Sync semantics (issue #317).
func (m *MultiEnforcer) Allow(ctx context.Context, prefix netip.Prefix) error {
	var errs []error
	for _, e := range m.enforcers {
		s, ok := e.(AllowlistSyncer)
		if !ok {
			continue
		}
		if err := s.Allow(ctx, prefix); err != nil {
			slog.WarnContext(ctx, "enforce/multi: Allow failed", "enforcer", e.Name(), "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Unallow forwards the allowlist removal to every AllowlistSyncer enforcer.
func (m *MultiEnforcer) Unallow(ctx context.Context, prefix netip.Prefix) error {
	var errs []error
	for _, e := range m.enforcers {
		s, ok := e.(AllowlistSyncer)
		if !ok {
			continue
		}
		if err := s.Unallow(ctx, prefix); err != nil {
			slog.WarnContext(ctx, "enforce/multi: Unallow failed", "enforcer", e.Name(), "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// SyncAllowlist forwards the desired allowlist state to every AllowlistSyncer
// enforcer.
func (m *MultiEnforcer) SyncAllowlist(ctx context.Context, want []netip.Prefix) error {
	var errs []error
	for _, e := range m.enforcers {
		s, ok := e.(AllowlistSyncer)
		if !ok {
			continue
		}
		if err := s.SyncAllowlist(ctx, want); err != nil {
			slog.WarnContext(ctx, "enforce/multi: SyncAllowlist failed", "enforcer", e.Name(), "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// LastSyncRepairs sums the optional SyncRepairReporter facet across every
// wrapped enforcer that implements it (issue #214). firstSync is true when
// ANY reporting child was on its boot reconcile — the daemon then skips the
// repair audit, since boot re-adds are expected restart recovery, not drift.
func (m *MultiEnforcer) LastSyncRepairs() (added, removed int, firstSync bool) {
	for _, e := range m.enforcers {
		r, ok := e.(SyncRepairReporter)
		if !ok {
			continue
		}
		a, rm, first := r.LastSyncRepairs()
		added += a
		removed += rm
		firstSync = firstSync || first
	}
	return added, removed, firstSync
}
