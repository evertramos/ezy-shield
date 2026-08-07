package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// EmailNotifier sends alert Notifications via SMTP.
// It supports STARTTLS (RFC 3207, port 587), implicit TLS (port 465), and plaintext.
// The SMTP password is resolved from a SecretRef before construction and is never
// stored in config files, logs, or error strings.
type EmailNotifier struct {
	from     string
	to       []string
	host     string
	port     int
	username string
	password string
	tlsMode  string // "starttls" | "tls" | "none"
	// dialAndSend is injectable for testing; set to nil to use the real SMTP path.
	dialAndSend func(ctx context.Context, addr, from string, to []string, body []byte) error
}

// NewEmail constructs an EmailNotifier.
// password is the already-resolved credential value (not the env reference).
// tlsMode must be "starttls", "tls", or "none"; empty defaults to "starttls".
func NewEmail(from string, to []string, host string, port int,
	username, password, tlsMode string,
) *EmailNotifier {
	if tlsMode == "" {
		tlsMode = "starttls"
	}
	e := &EmailNotifier{
		from:     from,
		to:       to,
		host:     host,
		port:     port,
		username: username,
		password: password,
		tlsMode:  tlsMode,
	}
	e.dialAndSend = e.realDialAndSend
	return e
}

// Name implements sdk.Notifier.
func (e *EmailNotifier) Name() string { return "email" }

// Send formats msg as a plain-text email and delivers it to all configured recipients.
func (e *EmailNotifier) Send(ctx context.Context, msg sdk.Notification) error {
	body := formatEmailBody(msg)
	subject := fmt.Sprintf("[EzyShield] %s: %s", strings.ToUpper(msg.Severity), capLen(msg.Title, 200))
	raw := buildRawEmail(e.from, e.to, subject, body)
	addr := fmt.Sprintf("%s:%d", e.host, e.port)
	if err := e.dialAndSend(ctx, addr, e.from, e.to, raw); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	return nil
}

// realDialAndSend delivers raw MIME via SMTP, choosing the TLS mode from config.
func (e *EmailNotifier) realDialAndSend(ctx context.Context, addr, from string, to []string, body []byte) error {
	switch e.tlsMode {
	case "tls":
		return e.sendImplicitTLS(ctx, addr, from, to, body)
	case "none":
		return e.sendPlaintext(ctx, addr, from, to, body)
	default: // "starttls"
		return e.sendSTARTTLS(ctx, addr, from, to, body)
	}
}

func (e *EmailNotifier) sendSTARTTLS(ctx context.Context, addr, from string, to []string, body []byte) error {
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close() //nolint:errcheck
	// Fail closed when STARTTLS is unavailable (issue #360): the operator
	// chose tls: "starttls", so silently delivering in plaintext — whether
	// the server never offered it or a MITM stripped the capability — would
	// downgrade the configured security mode and leak credentials on the
	// wire without any signal. An operator who genuinely wants plaintext can
	// set tls: "none" explicitly.
	ok, _ := c.Extension("STARTTLS")
	if !ok {
		return fmt.Errorf("starttls: server did not advertise STARTTLS; refusing to send in plaintext (set tls: \"none\" to allow, or fix the server)")
	}
	tlsCfg := &tls.Config{ServerName: e.host, MinVersion: tls.VersionTLS12} //nolint:gosec
	if err := c.StartTLS(tlsCfg); err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	return e.authAndDeliver(c, from, to, body)
}

func (e *EmailNotifier) sendImplicitTLS(ctx context.Context, addr, from string, to []string, body []byte) error {
	tlsCfg := &tls.Config{ServerName: e.host, MinVersion: tls.VersionTLS12} //nolint:gosec
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 15 * time.Second},
		Config:    tlsCfg,
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("tls dial %s: %w", addr, err)
	}
	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close() //nolint:errcheck
	return e.authAndDeliver(c, from, to, body)
}

func (e *EmailNotifier) sendPlaintext(ctx context.Context, addr, from string, to []string, body []byte) error {
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close() //nolint:errcheck
	return e.authAndDeliver(c, from, to, body)
}

func (e *EmailNotifier) authAndDeliver(c *smtp.Client, from string, to []string, body []byte) error {
	if e.username != "" && e.password != "" {
		auth := smtp.PlainAuth("", e.username, e.password, e.host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", addr, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := wc.Write(body); err != nil {
		_ = wc.Close()
		return fmt.Errorf("write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("close DATA: %w", err)
	}
	return c.Quit()
}

// formatEmailBody renders a plain-text body for the given Notification.
func formatEmailBody(msg sdk.Notification) string {
	var sb strings.Builder
	sb.WriteString("EzyShield Security Alert\n")
	sb.WriteString("========================\n\n")
	fmt.Fprintf(&sb, "Severity : %s\n", msg.Severity)
	fmt.Fprintf(&sb, "Title    : %s\n", capLen(msg.Title, maxFieldLen))
	if a := msg.Action; a != nil {
		fmt.Fprintf(&sb, "Action   : %s\n", a.Op)
		if a.IP.IsValid() {
			fmt.Fprintf(&sb, "IP       : %s\n", a.IP.String())
		}
		if a.Strike > 0 {
			fmt.Fprintf(&sb, "Strike   : %d\n", a.Strike)
		}
		if a.TTL > 0 {
			fmt.Fprintf(&sb, "TTL      : %s\n", a.TTL)
		}
		if a.Reason != "" {
			fmt.Fprintf(&sb, "Reason   : %s\n", capLen(a.Reason, maxFieldLen))
		}
	}
	if msg.Body != "" {
		fmt.Fprintf(&sb, "\nDetails:\n%s\n", capLen(msg.Body, maxFieldLen))
	}
	sb.WriteString("\n--\nSent by EzyShield\n")
	return sb.String()
}

// sanitizeHeader strips CR, LF, and every other ASCII control character from a
// header value (CWE-93, issue #320). Notification.Title is untrusted — the
// daemon passes wrapped error text into it — and email is the only
// line-oriented channel: an embedded CR/LF would terminate the Subject header
// and inject arbitrary headers (e.g. Bcc) into the message. Runs of stripped
// characters collapse to a single space so multi-line error text stays
// readable on one header line.
func sanitizeHeader(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	lastStripped := false
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			if !lastStripped {
				b.WriteRune(' ')
				lastStripped = true
			}
			continue
		}
		b.WriteRune(r)
		lastStripped = false
	}
	return strings.TrimSpace(b.String())
}

// buildRawEmail constructs a minimal RFC 5322 message in memory. Header values
// pass through sanitizeHeader at this choke point so no caller can smuggle a
// header-terminating CR/LF, wherever the value originated. The body is
// canonicalized here for the same reason: no caller-supplied CR may reach the
// DATA stream except as part of the CRLF line endings written below.
func buildRawEmail(from string, to []string, subject, body string) []byte {
	var sb strings.Builder
	fmt.Fprintf(&sb, "From: %s\r\n", sanitizeHeader(from))
	fmt.Fprintf(&sb, "To: %s\r\n", sanitizeHeader(strings.Join(to, ", ")))
	fmt.Fprintf(&sb, "Subject: %s\r\n", sanitizeHeader(subject))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	sb.WriteString("\r\n")
	// Normalize line endings to CRLF per RFC 5321. First fold CRLF to LF,
	// then neutralize every remaining bare CR (issue #403, body-side sibling
	// of #320): textproto's DotWriter forwards lone CRs to the wire
	// unchanged, and relays of the 2023 SMTP-smuggling class treat a lone CR
	// as an end-of-line, turning log-derived text like "x\r.\rQUIT" into a
	// DATA-termination primitive. Replacing with a space (as sanitizeHeader
	// does) keeps the surrounding text readable.
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\r", " ")
	for _, line := range strings.Split(body, "\n") {
		sb.WriteString(line + "\r\n")
	}
	return []byte(sb.String())
}
