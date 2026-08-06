package notify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
)

// redactTransportErr strips the request URL from an HTTP transport error
// before it is wrapped, logged, or shown to the user (Hard Rule 3, issue #319).
//
// http.Client.Do always returns *url.Error, whose Error() embeds the full
// request URL — and so does http.NewRequestWithContext when the URL fails to
// parse (Op:"parse", e.g. a control char in an untrimmed secret), so BOTH
// error paths must pass through here. For Telegram the bot token is a URL
// path segment; for Slack/Discord/generic webhooks the entire URL is a
// secret capability.
// net/http redacts only userinfo passwords — never path or query — so the raw
// error must not propagate: the dispatcher slog-logs it and `test notify`
// prints it to the terminal.
//
// keepHost controls how much survives. For channels with a well-known public
// API host (Telegram, Slack, Discord) the scheme+host aid debugging and are
// not secret, so only the path/query is dropped. For a generic webhook the
// operator's host can itself be secret (an internal name, or a capability URL
// on an obscure host), so the whole URL collapses to "[redacted]" (issue #360
// / Strix review of #319, CWE-209).
func redactTransportErr(err error, keepHost bool) error {
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
