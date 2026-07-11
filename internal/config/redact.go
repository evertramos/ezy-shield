package config

// RedactedMarker replaces any value that could hold a credential when the
// config is rendered for display (`config show`). It matches the marker
// returned by Secret.String() so every redaction path emits one grep-able
// string.
const RedactedMarker = "<redacted>"

// Redacted returns a view of c that is safe to render for the operator:
// every field that can legally carry a credential VALUE is replaced with
// RedactedMarker.
//
// SecretRef fields are left as-is: the loader rejects inline values at parse
// time, so they only ever hold an "env:VARNAME" reference — and the variable
// NAME is what makes the output actionable, not a secret.
//
// The one field family that CAN hold raw credentials is
// notify.webhook.headers: values are forwarded verbatim as HTTP headers
// (e.g. an Authorization bearer token) with no env-reference enforcement,
// so every header value is redacted; keys are preserved. Any future config
// field that accepts a raw credential value must be added here and covered
// in redact_test.go.
//
// The returned Config shares all other sub-structs with c — callers must
// treat it as read-only.
func (c *Config) Redacted() *Config {
	if c == nil {
		return nil
	}
	out := *c
	if c.Notify != nil && c.Notify.Webhook != nil && len(c.Notify.Webhook.Headers) > 0 {
		notify := *c.Notify
		webhook := *c.Notify.Webhook
		webhook.Headers = make(map[string]string, len(c.Notify.Webhook.Headers))
		for k := range c.Notify.Webhook.Headers {
			webhook.Headers[k] = RedactedMarker
		}
		notify.Webhook = &webhook
		out.Notify = &notify
	}
	return &out
}
