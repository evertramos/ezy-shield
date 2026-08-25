// Package httpx holds small HTTP helpers shared across packages whose
// behavior is security-sensitive enough that duplication would be a risk.
//
// RedactTransportErr existed as two independent near-copies —
// internal/notify.redactTransportErr (#319/#389) and
// internal/enrich.redactURLErr (#294/#436) — and a hardening applied to one
// could silently miss the other (issue #439). Both now delegate here; the
// per-package secret-leak gates keep guarding their call sites.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
)

// RedactTransportErr strips the request URL from an HTTP transport error
// before it is wrapped, logged, or shown to an operator (Hard Rule 3,
// SECURITY-REVIEW §4).
//
// http.Client.Do always returns *url.Error, whose Error() embeds the full
// request URL — and so does http.NewRequestWithContext when the URL fails to
// parse — so BOTH error paths must pass through here. net/http redacts only
// userinfo passwords, never path or query, so the raw error must not
// propagate: secrets ride in URL paths (Telegram bot tokens), queries
// (MaxMind license keys), or the whole URL (webhook capability URLs).
//
// keepHost controls how much survives. For a well-known public API host
// (Telegram, Slack, Discord, MaxMind) scheme+host aid debugging and are not
// secret, so only the path/query is dropped. For a generic webhook the
// operator's host can itself be secret (an internal name, or a capability
// URL on an obscure host), so the whole URL collapses to "[redacted]" and
// the transport cause is reduced to a fixed classification (issue #360,
// CWE-209).
func RedactTransportErr(err error, keepHost bool) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	if keepHost {
		redacted := "[redacted]"
		if u, perr := url.Parse(ue.URL); perr == nil && u.Host != "" {
			redacted = u.Scheme + "://" + u.Host + "/[redacted]"
		}
		return fmt.Errorf("%s %s: %w", ue.Op, redacted, ue.Err)
	}
	// keepHost=false: the cause text (ue.Err) can name the host (DNS errors:
	// "lookup <host>: no such host") or the RESOLVED address (dial errors:
	// "dial tcp 192.0.2.1:443: connect: connection refused" — Go never puts
	// the hostname there), and a generic webhook host is itself potentially
	// secret. Text scrubbing cannot cover the resolved-IP case, so the cause
	// is never echoed: it collapses to a fixed classification. The errors.Is
	// chain to ue.Err is intentionally dropped here.
	return fmt.Errorf("%s [redacted]: %s", ue.Op, classifyCause(ue.Err))
}

// classifyCause maps a transport-level cause onto a fixed, address-free label.
// Only these constant strings can ever reach logs/terminal for keepHost=false;
// no byte of the cause's own text (which may embed hostname or resolved
// IP:port) is echoed.
func classifyCause(err error) string {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		if dnsErr.IsNotFound {
			return "no such host"
		}
		return "dns error"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "transport error"
}
