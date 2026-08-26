package decision

// Verified-bot guard (issue #215): forward-confirmed reverse DNS protection
// for well-known crawlers. Anti-lockout protects the operator; this protects
// Googlebot/Bingbot/etc from an over-eager rule — banning Googlebot is one
// of the most damaging false positives a site owner can suffer, and naive
// User-Agent allowlisting is spoofable. The check runs ONLY at decision time
// on the ban path (never in the hot parse path), and only when the IP's own
// traffic claimed a known bot User-Agent; the daemon supplies UA-claim
// extraction and the FCrDNS verification via the injected callback, keeping
// DNS entirely out of this package.
//
// Safety ordering: the guard sits AFTER the allowlist and anti-lockout
// checks (which always win) and only ever converts a would-be ban into an
// audited "record" — it can never cause a ban, escalate one, or touch the
// allowlist. A failed or timed-out verification means the UA claim is
// simply ignored: the spoofer proceeds down the normal ban path.

import (
	"net/netip"

	"context"
)

// ReasonVerifiedBotSpared is the Action.Reason prefix Decide emits when
// FCrDNS verification confirmed the candidate is the bot its traffic
// claimed, and the ban was spared. The provider name follows after ": ".
const ReasonVerifiedBotSpared = "verified-bot spared"

// SetBotVerifier injects the verified-bot check (issue #215). fn receives
// the ban-candidate IP and reports the confirmed provider name and whether
// the ban should be spared; nil (the default) disables the guard.
// Implementations must be bounded (timeouts, caching) — Decide calls this
// synchronously on the ban path. Call before the engine starts deciding.
func (e *Engine) SetBotVerifier(fn func(ctx context.Context, ip netip.Addr) (provider string, spared bool)) {
	e.botVerify = fn
}
