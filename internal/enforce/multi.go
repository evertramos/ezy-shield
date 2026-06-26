package enforce

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
