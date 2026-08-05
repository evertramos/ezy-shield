package notify

import (
	"errors"
	"fmt"
	"net/url"
)

// redactTransportErr strips the request URL from an HTTP transport error
// before it is wrapped, logged, or shown to the user (Hard Rule 3, issue #319).
//
// http.Client.Do always returns *url.Error, whose Error() embeds the full
// request URL. For Telegram the bot token is a URL path segment; for
// Slack/Discord/generic webhooks the entire URL is a secret capability.
// net/http redacts only userinfo passwords — never path or query — so the raw
// error must not propagate: the dispatcher slog-logs it and `test notify`
// prints it to the terminal. Scheme and host are kept (useful for debugging,
// never secret); everything after the host is dropped.
func redactTransportErr(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	redacted := "[redacted]"
	if u, perr := url.Parse(ue.URL); perr == nil && u.Host != "" {
		redacted = u.Scheme + "://" + u.Host + "/[redacted]"
	}
	return fmt.Errorf("%s %s: %w", ue.Op, redacted, ue.Err)
}
