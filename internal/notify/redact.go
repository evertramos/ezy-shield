package notify

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// redactTransportErr strips the request URL from an HTTP transport error
// before it is wrapped, logged, or shown to the user (Hard Rule 3, issue #319).
//
// http.Client.Do always returns *url.Error, whose Error() embeds the full
// request URL. For Telegram the bot token is a URL path segment; for
// Slack/Discord/generic webhooks the entire URL is a secret capability.
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
	redacted := "[redacted]"
	host := ""
	if u, perr := url.Parse(ue.URL); perr == nil {
		host = u.Host
		if keepHost && host != "" {
			redacted = u.Scheme + "://" + host + "/[redacted]"
		}
	}
	if keepHost {
		return fmt.Errorf("%s %s: %w", ue.Op, redacted, ue.Err)
	}
	// keepHost=false: the underlying dial/DNS error (ue.Err) can itself name
	// the host (e.g. "lookup <host>: no such host"), so scrub the host from
	// the cause and don't wrap it — a generic webhook host is potentially
	// secret. The error kind (refused/timeout/no such host) survives; the
	// errors.Is chain to ue.Err is intentionally dropped here.
	cause := ue.Err.Error()
	if host != "" {
		cause = strings.ReplaceAll(cause, host, "[redacted]")
		if h, _, ok := strings.Cut(host, ":"); ok && h != "" {
			cause = strings.ReplaceAll(cause, h, "[redacted]")
		}
	}
	return fmt.Errorf("%s %s: %s", ue.Op, redacted, cause)
}
