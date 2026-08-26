// SPDX-License-Identifier: AGPL-3.0-only

package enforce

// allowlist.go — optional allowlist-mirroring side of an Enforcer (issue #317).

import (
	"context"
	"net/netip"
)

// AllowlistSyncer is the optional interface an Enforcer implements to mirror
// the daemon's allowlist into local firewall state — the nftables @allowed /
// @allowed6 sets that back the ADR-0007 layer-4 anti-lockout accept rules.
// It is structurally identical to the daemon's private allowlistSyncer
// assertion, so satisfying one satisfies the other. Kept out of sdk.Enforcer
// proper because edge enforcers (Cloudflare) have no matching concept.
//
// Wrapper enforcers (Gate, MultiEnforcer) MUST forward these methods:
// hiding them makes the daemon's type assertion fail and silently disables
// the kernel-level anti-lockout backstop (issue #317).
type AllowlistSyncer interface {
	Allow(ctx context.Context, prefix netip.Prefix) error
	Unallow(ctx context.Context, prefix netip.Prefix) error
	SyncAllowlist(ctx context.Context, want []netip.Prefix) error
}

// Compile-time guards: the local-firewall enforcer and both wrappers must
// keep the allowlist mirror visible to the daemon's type assertion.
var (
	_ AllowlistSyncer = (*NftablesEnforcer)(nil)
	_ AllowlistSyncer = (*Gate)(nil)
	_ AllowlistSyncer = (*MultiEnforcer)(nil)
)
