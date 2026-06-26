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
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: e.host, MinVersion: tls.VersionTLS12} //nolint:gosec
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
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

// buildRawEmail constructs a minimal RFC 5322 message in memory.
func buildRawEmail(from string, to []string, subject, body string) []byte {
	var sb strings.Builder
	fmt.Fprintf(&sb, "From: %s\r\n", from)
	fmt.Fprintf(&sb, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&sb, "Subject: %s\r\n", subject)
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	sb.WriteString("\r\n")
	// Normalize line endings to CRLF per RFC 5321.
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		sb.WriteString(line + "\r\n")
	}
	return []byte(sb.String())
}
