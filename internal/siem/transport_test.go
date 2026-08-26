package siem

// Transport tests (issue #203): in-test TCP/UDS/UDP/TLS servers asserting
// framing, queue overflow drop behavior, and shutdown flush. -race clean.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func testEvent(action string) Event {
	return Event{
		Time:   time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
		Action: action,
		IP:     netip.MustParseAddr("192.0.2.7"),
		Rule:   "ssh_bruteforce",
		Score:  85,
		Strike: 2,
		TTL:    time.Hour,
		Actor:  "rules",
	}
}

func testIdentity() Identity {
	return Identity{Node: "host1", Vendor: "ezy", Product: "EzyShield", Version: "test"}
}

// runForwarder starts f.Run and returns a stop function that cancels and
// waits for the flush to finish.
func runForwarder(t *testing.T, f *Forwarder) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.Run(ctx)
		close(done)
	}()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("forwarder did not stop")
		}
	}
}

// lineCollector accepts stream connections and records newline-framed lines.
type lineCollector struct {
	mu    sync.Mutex
	lines []string
}

func (c *lineCollector) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close() //nolint:errcheck
			sc := bufio.NewScanner(conn)
			for sc.Scan() {
				c.mu.Lock()
				c.lines = append(c.lines, sc.Text())
				c.mu.Unlock()
			}
		}(conn)
	}
}

func (c *lineCollector) wait(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := len(c.lines)
		c.mu.Unlock()
		if got >= n {
			c.mu.Lock()
			defer c.mu.Unlock()
			return append([]string(nil), c.lines...)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d lines", n)
	return nil
}

func TestTCP_JSONNewlineFraming(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	col := &lineCollector{}
	go col.serve(ln)

	f, err := NewForwarder([]SinkConfig{{
		Name: "t", Address: "tcp://" + ln.Addr().String(), Format: "json",
	}}, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := runForwarder(t, f)
	f.Emit(testEvent("ban"))
	f.Emit(testEvent("unban"))
	lines := col.wait(t, 2)
	stop()

	for _, l := range lines {
		if !strings.HasPrefix(l, "{") || !strings.Contains(l, `"action"`) {
			t.Errorf("line is not a JSON event: %q", l)
		}
	}
	if !strings.Contains(lines[0], `"ban"`) || !strings.Contains(lines[1], `"unban"`) {
		t.Errorf("event order/content wrong: %v", lines)
	}
}

// TestTCP_RFC5424OctetCounting asserts RFC 6587 octet-counting framing:
// "<len> <msg>" with len exactly the byte count of msg.
func TestTCP_RFC5424OctetCounting(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type frame struct {
		declared int
		msg      string
	}
	frames := make(chan frame, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		br := bufio.NewReader(conn)
		for {
			lenStr, err := br.ReadString(' ')
			if err != nil {
				return
			}
			n, err := strconv.Atoi(strings.TrimSpace(lenStr))
			if err != nil {
				return
			}
			buf := make([]byte, n)
			if _, err := readFull(br, buf); err != nil {
				return
			}
			frames <- frame{declared: n, msg: string(buf)}
		}
	}()

	f, err := NewForwarder([]SinkConfig{{
		Name: "s", Address: "tcp://" + ln.Addr().String(), Format: "rfc5424",
	}}, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := runForwarder(t, f)
	f.Emit(testEvent("ban"))
	select {
	case fr := <-frames:
		if fr.declared != len(fr.msg) {
			t.Errorf("declared length %d != actual %d", fr.declared, len(fr.msg))
		}
		if !strings.HasPrefix(fr.msg, "<") || !strings.Contains(fr.msg, "EzyShield") {
			t.Errorf("frame is not RFC5424 syslog: %q", fr.msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no frame received")
	}
	stop()
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestUDP_OneDatagramPerEvent(t *testing.T) {
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	got := make(chan string, 4)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n])
		}
	}()

	f, err := NewForwarder([]SinkConfig{{
		Name: "u", Address: "udp://" + pc.LocalAddr().String(), Format: "cef",
	}}, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := runForwarder(t, f)
	f.Emit(testEvent("ban"))
	select {
	case msg := <-got:
		if !strings.HasPrefix(msg, "CEF:0|") {
			t.Errorf("datagram is not CEF: %q", msg)
		}
		if strings.HasSuffix(msg, "\n") {
			t.Errorf("datagram must be unframed (no trailing newline): %q", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no datagram received")
	}
	stop()
}

func TestUDSStream_Framing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "siem.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	col := &lineCollector{}
	go col.serve(ln)

	f, err := NewForwarder([]SinkConfig{{
		Name: "x", Address: "uds://" + path, Format: "json",
	}}, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := runForwarder(t, f)
	f.Emit(testEvent("ban"))
	lines := col.wait(t, 1)
	stop()
	if !strings.Contains(lines[0], `"ban"`) {
		t.Errorf("uds stream line = %q", lines[0])
	}
}

func TestUDSDatagram_Fallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "siemgram.sock")
	addr, err := net.ResolveUnixAddr("unixgram", path)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	got := make(chan string, 2)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n])
		}
	}()

	f, err := NewForwarder([]SinkConfig{{
		Name: "g", Address: "uds://" + path, Format: "json",
	}}, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := runForwarder(t, f)
	f.Emit(testEvent("ban"))
	select {
	case msg := <-got:
		if !strings.Contains(msg, `"ban"`) {
			t.Errorf("datagram = %q", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no datagram on unixgram socket")
	}
	stop()
}

func TestFileSink_Appends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	f, err := NewForwarder([]SinkConfig{{
		Name: "f", Address: "file://" + path, Format: "json",
	}}, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := runForwarder(t, f)
	f.Emit(testEvent("ban"))
	f.Emit(testEvent("unban"))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, _ := os.ReadFile(path); strings.Count(string(b), "\n") >= 2 { //nolint:gosec // test temp file
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	b, err := os.ReadFile(path) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"ban"`) {
		t.Fatalf("file content = %q", string(b))
	}
}

// TestTLS_HandshakeWithPinnedCA spins a TLS server with a self-signed cert
// and pins it via ca_file. ServerName verification stays ON throughout.
func TestTLS_HandshakeWithPinnedCA(t *testing.T) {
	certPEM, keyPEM := makeSelfSignedCert(t, "localhost")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	col := &lineCollector{}
	go col.serve(ln)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	f, err := NewForwarder([]SinkConfig{{
		Name:    "tls",
		Address: "tls://localhost:" + port,
		Format:  "json",
		CAFile:  caFile,
	}}, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := runForwarder(t, f)
	f.Emit(testEvent("ban"))
	lines := col.wait(t, 1)
	stop()
	if !strings.Contains(lines[0], `"ban"`) {
		t.Errorf("tls line = %q", lines[0])
	}
}

// TestTLS_WrongNameRefused pins that ServerName verification is never
// disabled: a cert for another name must fail and the event queues/drops
// rather than being sent.
func TestTLS_WrongNameRefused(t *testing.T) {
	certPEM, keyPEM := makeSelfSignedCert(t, "other.example")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	f, err := NewForwarder([]SinkConfig{{
		Name:    "tls",
		Address: "tls://localhost:" + port, // cert says other.example
		Format:  "json",
		CAFile:  caFile,
	}}, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := runForwarder(t, f)
	f.Emit(testEvent("ban"))
	// Give delivery a moment to attempt + fail; then stop. The flush drop
	// or retry-drop counter must register the undelivered event.
	time.Sleep(300 * time.Millisecond)
	stop()
	if f.Drops()["tls"] == 0 {
		t.Fatal("event was delivered (or not counted) despite ServerName mismatch")
	}
}

// TestQueueOverflow_DropOldest fills the queue against a stalled sink and
// asserts drop-oldest semantics + the drop counter.
func TestQueueOverflow_DropOldest(t *testing.T) {
	// file sink pointed at an un-creatable path stalls every delivery.
	f, err := NewForwarder([]SinkConfig{{
		Name:      "q",
		Address:   "file:///nonexistent-dir-ezyshield-test/out.log",
		Format:    "json",
		QueueSize: 4,
	}}, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// No Run: the queue just fills.
	for i := 0; i < 10; i++ {
		e := testEvent("ban")
		e.Rule = fmt.Sprintf("rule-%d", i)
		f.Emit(e)
	}
	if drops := f.Drops()["q"]; drops != 6 {
		t.Fatalf("drops = %d, want 6 (10 emitted into a queue of 4)", drops)
	}
	// The queue must hold the NEWEST 4 (oldest dropped).
	s := f.sinks[0]
	var got []string
	for len(s.q) > 0 {
		e := <-s.q
		got = append(got, e.Rule)
	}
	want := []string{"rule-6", "rule-7", "rule-8", "rule-9"}
	if len(got) != 4 {
		t.Fatalf("queued = %v, want 4 newest", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("queued = %v, want %v (drop-OLDEST)", got, want)
		}
	}
}

// TestShutdownFlush pins that events still queued at cancellation get one
// bounded delivery attempt.
func TestShutdownFlush(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flush.log")
	f, err := NewForwarder([]SinkConfig{{
		Name: "fl", Address: "file://" + path, Format: "json",
	}}, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Queue events BEFORE Run starts, then run+cancel immediately: the
	// worker's shutdown flush must deliver them.
	f.Emit(testEvent("ban"))
	f.Emit(testEvent("unban"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		f.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	b, err := os.ReadFile(path) //nolint:gosec // test temp file
	if err != nil {
		t.Fatalf("flush wrote nothing: %v", err)
	}
	if strings.Count(string(b), "\n") != 2 {
		t.Fatalf("flush delivered %q, want 2 events", string(b))
	}
}

func TestEventFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "filtered.log")
	f, err := NewForwarder([]SinkConfig{{
		Name: "flt", Address: "file://" + path, Format: "json",
		Events: []string{"ban", "unban"},
	}}, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := runForwarder(t, f)
	f.Emit(testEvent("ban"))
	f.Emit(testEvent("allow"))  // filtered out
	f.Emit(testEvent("expire")) // filtered out
	f.Emit(testEvent("unban"))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, _ := os.ReadFile(path); strings.Count(string(b), "\n") >= 2 { //nolint:gosec // test temp file
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	b, _ := os.ReadFile(path) //nolint:gosec // test temp file
	if strings.Count(string(b), "\n") != 2 || strings.Contains(string(b), `"allow"`) {
		t.Fatalf("filter failed: %q", string(b))
	}
}

func TestParseAddress(t *testing.T) {
	cases := []struct {
		in      string
		scheme  string
		target  string
		wantErr bool
	}{
		{in: "udp://siem.example:514", scheme: "udp", target: "siem.example:514"},
		{in: "tcp://siem.example:601", scheme: "tcp", target: "siem.example:601"},
		{in: "tls://siem.example:6514", scheme: "tls", target: "siem.example:6514"},
		{in: "uds:///run/collector.sock", scheme: "uds", target: "/run/collector.sock"},
		{in: "file:///var/log/forward.log", scheme: "file", target: "/var/log/forward.log"},
		{in: "http://siem.example", wantErr: true},
		{in: "tcp://noport", wantErr: true},
		{in: "uds://relative.sock", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tc := range cases {
		scheme, target, err := ParseAddress(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseAddress(%q): want error", tc.in)
			}
			continue
		}
		if err != nil || scheme != tc.scheme || target != tc.target {
			t.Errorf("ParseAddress(%q) = %q,%q,%v; want %q,%q", tc.in, scheme, target, err, tc.scheme, tc.target)
		}
	}
}

// makeSelfSignedCert generates a minimal cert/key pair for hostname.
func makeSelfSignedCert(t *testing.T, hostname string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
