package notify_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// smtpSession captures a single SMTP delivery (envelope + message body).
type smtpSession struct {
	From string
	To   []string
	Body string
}

// fakeSMTP is a minimal SMTP server that accepts plaintext SMTP connections,
// records deliveries, and responds with RFC 5321-compliant reply codes.
// It is used only in tests; it does not implement TLS or AUTH.
type fakeSMTP struct {
	mu       sync.Mutex
	sessions []smtpSession
	ln       net.Listener
}

func newFakeSMTP(t *testing.T) (*fakeSMTP, string) {
	t.Helper()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakeSMTP: listen: %v", err)
	}
	f := &fakeSMTP{ln: ln}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return f, ln.Addr().String()
}

func (f *fakeSMTP) recorded() []smtpSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]smtpSession, len(f.sessions))
	copy(out, f.sessions)
	return out
}

func (f *fakeSMTP) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	writeLine := func(s string) {
		_, _ = fmt.Fprintln(w, s)
		_ = w.Flush()
	}

	writeLine("220 fakeSMTP ESMTP ready")

	var sess smtpSession
	inData := false
	var dataLines []string

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if inData {
			if line == "." {
				sess.Body = strings.Join(dataLines, "\n")
				f.mu.Lock()
				f.sessions = append(f.sessions, sess)
				f.mu.Unlock()
				sess = smtpSession{}
				dataLines = nil
				inData = false
				writeLine("250 OK")
				continue
			}
			// Dot-unstuffing per RFC 5321 §4.5.2.
			line = strings.TrimPrefix(line, ".")
			dataLines = append(dataLines, line)
			continue
		}

		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO") || strings.HasPrefix(cmd, "HELO"):
			writeLine("250-fakeSMTP\r\n250 OK")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			addr := extractAngle(line[len("MAIL FROM:"):])
			sess.From = addr
			writeLine("250 OK")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			addr := extractAngle(line[len("RCPT TO:"):])
			sess.To = append(sess.To, addr)
			writeLine("250 OK")
		case strings.HasPrefix(cmd, "DATA"):
			writeLine("354 End data with <CRLF>.<CRLF>")
			inData = true
		case strings.HasPrefix(cmd, "QUIT"):
			writeLine("221 Bye")
			return
		default:
			writeLine("500 Unknown command")
		}
	}
}

func extractAngle(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
}

// newTestEmail creates an EmailNotifier pointed at the fake SMTP server.
// It uses the injected send path (tlsMode="none") so no TLS handshake is needed.
func newTestEmail(t *testing.T, addr string) *notify.EmailNotifier {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	if _, err := fmt.Sscan(portStr, &port); err != nil {
		t.Fatalf("bad addr %q: %v", addr, err)
	}
	return notify.NewEmail(
		"shield@example.com",
		[]string{"admin@example.com"},
		host, port,
		"", "", // no auth on fake server
		"none",
	)
}

// ── Basic send ────────────────────────────────────────────────────────────────

func TestEmail_SendsMessage(t *testing.T) {
	srv, addr := newFakeSMTP(t)
	n := newTestEmail(t, addr)

	msg := sdk.Notification{Severity: "warn", Title: "SSH attack detected"}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	sessions := srv.recorded()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 SMTP session, got %d", len(sessions))
	}
	s := sessions[0]
	if s.From != "shield@example.com" {
		t.Errorf("MAIL FROM: want shield@example.com, got %q", s.From)
	}
	if len(s.To) != 1 || s.To[0] != "admin@example.com" {
		t.Errorf("RCPT TO: want [admin@example.com], got %v", s.To)
	}
	if !strings.Contains(s.Body, "EzyShield") {
		t.Errorf("body should mention EzyShield:\n%s", s.Body)
	}
	if !strings.Contains(s.Body, "SSH attack detected") {
		t.Errorf("body should contain title:\n%s", s.Body)
	}
}

func TestEmail_IncludesActionFields(t *testing.T) {
	srv, addr := newFakeSMTP(t)
	n := newTestEmail(t, addr)

	ip := netip.MustParseAddr("10.20.30.40")
	msg := sdk.Notification{
		Severity: "critical",
		Title:    "IP banned",
		Action: &sdk.Action{
			IP:     ip,
			Op:     "ban",
			Strike: 4,
			TTL:    7 * 24 * time.Hour,
			Reason: "port scanning",
		},
	}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	body := srv.recorded()[0].Body
	for _, want := range []string{"10.20.30.40", "4", "168h", "port scanning", "ban"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}

func TestEmail_SubjectContainsSeverity(t *testing.T) {
	srv, addr := newFakeSMTP(t)
	n := newTestEmail(t, addr)

	_ = n.Send(context.Background(), sdk.Notification{Severity: "critical", Title: "oops"})
	body := srv.recorded()[0].Body
	if !strings.Contains(body, "Subject:") {
		t.Error("body should include a Subject header")
	}
	if !strings.Contains(body, "CRITICAL") {
		t.Errorf("subject should contain severity: %s", body)
	}
}

func TestEmail_Name(t *testing.T) {
	n := notify.NewEmail("a@b.com", []string{"c@d.com"}, "localhost", 25, "", "", "none")
	if n.Name() != "email" {
		t.Errorf("expected Name()=email, got %q", n.Name())
	}
}

// ── Field length cap ──────────────────────────────────────────────────────────

func TestEmail_LongReasonTruncated(t *testing.T) {
	srv, addr := newFakeSMTP(t)
	n := newTestEmail(t, addr)

	longReason := strings.Repeat("A", 2000)
	ip := netip.MustParseAddr("1.1.1.1")
	msg := sdk.Notification{
		Severity: "warn", Title: "test",
		Action: &sdk.Action{IP: ip, Reason: longReason},
	}
	if err := n.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	body := srv.recorded()[0].Body
	if strings.Contains(body, longReason) {
		t.Error("2000-char reason was not truncated in email body")
	}
}

// ── Connection error ──────────────────────────────────────────────────────────

func TestEmail_UnreachableHostReturnsError(t *testing.T) {
	// Use a port on localhost that nothing is listening on.
	n := notify.NewEmail("a@b.com", []string{"c@d.com"}, "127.0.0.1", 19999, "", "", "none")
	err := n.Send(context.Background(), sdk.Notification{Severity: "info", Title: "t"})
	if err == nil {
		t.Fatal("expected error connecting to unreachable host, got nil")
	}
}
