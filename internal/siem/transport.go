// SPDX-License-Identifier: AGPL-3.0-only

package siem

// Forwarding transports (issue #203): deliver formatted events to SIEM
// endpoints. Outbound only — no listener is ever created here. The design
// constraint is that forwarding must NEVER block or destabilize the
// decision pipeline: Emit is non-blocking with a bounded per-sink queue
// (drop-oldest + counter when full), delivery runs in per-sink goroutines
// with reconnect-and-capped-backoff, and shutdown makes one bounded flush
// attempt.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultQueueSize bounds each sink's in-memory queue.
	DefaultQueueSize = 1024
	// MaxQueueSize is the config ceiling.
	MaxQueueSize = 65536
	// dialTimeout bounds one connection attempt.
	dialTimeout = 5 * time.Second
	// writeTimeout bounds one event write.
	writeTimeout = 5 * time.Second
	// flushDeadline bounds the shutdown flush attempt.
	flushDeadline = 3 * time.Second
	// backoffMax caps the reconnect backoff.
	backoffMax = 30 * time.Second
)

// ValidFormats enumerates the sink output formats.
var ValidFormats = map[string]bool{"json": true, "cef": true, "rfc5424": true}

// SinkConfig describes one SIEM destination. Mirrors the config.yaml
// section; validation lives in internal/config, and NewForwarder re-checks
// the load-bearing parts.
type SinkConfig struct {
	// Name identifies the sink in logs and drop counters.
	Name string
	// Address is scheme://target — udp://host:port, tcp://host:port,
	// tls://host:port, uds:///path (stream, falling back to datagram),
	// file:///path (append).
	Address string
	// Format is "json" (default), "cef", or "rfc5424".
	Format string
	// Events filters which audit ops are forwarded (empty = all).
	Events []string
	// CAFile optionally pins the CA bundle for tls:// (PEM file path).
	// Verification is NEVER disabled; this only replaces the system roots.
	CAFile string
	// QueueSize bounds the sink queue (0 = DefaultQueueSize).
	QueueSize int
}

// Identity is the emitting software/host identity stamped on every event.
type Identity struct {
	Node    string
	Vendor  string
	Product string
	Version string
}

// endpoint is a parsed sink address.
type endpoint struct {
	scheme string // udp | tcp | tls | uds | file
	target string // host:port or path
}

// ParseAddress validates and splits a sink address. Exported for config
// validation and doctor.
func ParseAddress(addr string) (scheme, target string, err error) {
	u, err := url.Parse(addr)
	if err != nil {
		return "", "", fmt.Errorf("siem: invalid address: %w", err)
	}
	switch u.Scheme {
	case "udp", "tcp", "tls":
		host := u.Host
		if host == "" {
			return "", "", fmt.Errorf("siem: %s:// address needs host:port", u.Scheme)
		}
		if _, _, err := net.SplitHostPort(host); err != nil {
			return "", "", fmt.Errorf("siem: %s:// address needs host:port: %w", u.Scheme, err)
		}
		return u.Scheme, host, nil
	case "uds", "file":
		path := u.Path
		if path == "" {
			// uds://relative or file://relative parse the token into Host.
			path = u.Host + u.Path
		}
		if path == "" || !strings.HasPrefix(path, "/") {
			return "", "", fmt.Errorf("siem: %s:// address needs an absolute path", u.Scheme)
		}
		return u.Scheme, path, nil
	default:
		return "", "", fmt.Errorf("siem: unsupported scheme %q (want udp|tcp|tls|uds|file)", u.Scheme)
	}
}

// Forwarder fans events out to every configured sink.
type Forwarder struct {
	sinks    []*sinkWorker
	identity Identity
	logger   *slog.Logger
}

// NewForwarder builds a forwarder for the given sinks. Invalid sink
// addresses fail construction — config validation should have caught them.
func NewForwarder(cfgs []SinkConfig, id Identity, logger *slog.Logger) (*Forwarder, error) {
	if logger == nil {
		logger = slog.Default()
	}
	f := &Forwarder{identity: id, logger: logger}
	for _, c := range cfgs {
		scheme, target, err := ParseAddress(c.Address)
		if err != nil {
			return nil, fmt.Errorf("sink %s: %w", c.Name, err)
		}
		format := c.Format
		if format == "" {
			format = "json"
		}
		if !ValidFormats[format] {
			return nil, fmt.Errorf("sink %s: unknown format %q", c.Name, format)
		}
		qs := c.QueueSize
		if qs <= 0 {
			qs = DefaultQueueSize
		}
		if qs > MaxQueueSize {
			qs = MaxQueueSize
		}
		events := map[string]bool{}
		for _, ev := range c.Events {
			events[ev] = true
		}
		f.sinks = append(f.sinks, &sinkWorker{
			name:   c.Name,
			ep:     endpoint{scheme: scheme, target: target},
			format: format,
			events: events,
			caFile: c.CAFile,
			q:      make(chan Event, qs),
			logger: logger,
		})
	}
	return f, nil
}

// Emit enqueues an event on every sink whose filter matches. Non-blocking:
// a full queue drops its OLDEST event and counts the drop — the pipeline is
// never back-pressured by a slow SIEM.
func (f *Forwarder) Emit(e Event) {
	if e.Node == "" {
		e.Node = f.identity.Node
	}
	if e.Vendor == "" {
		e.Vendor = f.identity.Vendor
	}
	if e.Product == "" {
		e.Product = f.identity.Product
	}
	if e.Version == "" {
		e.Version = f.identity.Version
	}
	for _, s := range f.sinks {
		if len(s.events) > 0 && !s.events[e.Action] {
			continue
		}
		s.enqueue(e)
	}
}

// Drops returns the per-sink dropped-event counters.
func (f *Forwarder) Drops() map[string]uint64 {
	out := make(map[string]uint64, len(f.sinks))
	for _, s := range f.sinks {
		out[s.name] = s.drops.Load()
	}
	return out
}

// Run delivers events until ctx is done, then makes one bounded flush
// attempt per sink and returns.
func (f *Forwarder) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, s := range f.sinks {
		wg.Add(1)
		go func(s *sinkWorker) {
			defer wg.Done()
			s.run(ctx)
		}(s)
	}
	wg.Wait()
}

// sinkWorker owns one destination: queue, connection, backoff.
type sinkWorker struct {
	name   string
	ep     endpoint
	format string
	events map[string]bool
	caFile string
	q      chan Event
	drops  atomic.Uint64
	logger *slog.Logger

	conn    net.Conn // nil = not connected (also the file handle via netFile)
	file    *os.File // file:// sink
	backoff time.Duration
}

// enqueue adds e, dropping the oldest queued event when full.
func (s *sinkWorker) enqueue(e Event) {
	select {
	case s.q <- e:
		return
	default:
	}
	// Full: drop the oldest to make room; if a concurrent reader emptied
	// the queue meanwhile, the second send almost always succeeds.
	select {
	case <-s.q:
		s.drops.Add(1)
	default:
	}
	select {
	case s.q <- e:
	default:
		s.drops.Add(1)
	}
}

func (s *sinkWorker) run(ctx context.Context) {
	defer s.closeConn()
	for {
		select {
		case <-ctx.Done():
			s.flush()
			return
		case e := <-s.q:
			s.deliver(ctx, e)
		}
	}
}

// flush makes one bounded attempt to drain the queue at shutdown.
func (s *sinkWorker) flush() {
	deadline := time.Now().Add(flushDeadline)
	for {
		select {
		case e := <-s.q:
			msg, err := s.render(e)
			if err != nil {
				continue
			}
			if time.Now().After(deadline) {
				s.drops.Add(1)
				continue // drain and count; no more writes after deadline
			}
			if err := s.writeOnce(msg, deadline); err != nil {
				s.drops.Add(1)
			}
		default:
			return
		}
	}
}

// deliver writes one event, reconnecting with capped backoff until it is
// written or ctx ends. The queue keeps absorbing (and, when full, dropping
// oldest) meanwhile — bounded memory, no pipeline back-pressure.
func (s *sinkWorker) deliver(ctx context.Context, e Event) {
	msg, err := s.render(e)
	if err != nil {
		s.logger.Warn("siem: format failed; event dropped", "sink", s.name, "err", err)
		return
	}
	for {
		err := s.writeOnce(msg, time.Now().Add(writeTimeout))
		if err == nil {
			s.backoff = 0
			return
		}
		s.closeConn()
		if s.backoff == 0 {
			s.backoff = time.Second
		} else if s.backoff < backoffMax {
			s.backoff *= 2
			if s.backoff > backoffMax {
				s.backoff = backoffMax
			}
		}
		s.logger.Warn("siem: delivery failed; retrying after backoff",
			"sink", s.name, "backoff", s.backoff, "err", err)
		select {
		case <-ctx.Done():
			s.drops.Add(1)
			return
		case <-time.After(s.backoff):
		}
	}
}

// render formats the event per the sink's format.
func (s *sinkWorker) render(e Event) ([]byte, error) {
	switch s.format {
	case "cef":
		return []byte(FormatCEF(e)), nil
	case "rfc5424":
		return []byte(FormatRFC5424(e)), nil
	default:
		return FormatJSON(e)
	}
}

// frame applies the on-the-wire framing for stream transports: RFC 6587
// octet counting for RFC 5424 syslog, newline framing otherwise.
func (s *sinkWorker) frame(msg []byte) []byte {
	if s.format == "rfc5424" {
		return append([]byte(strconv.Itoa(len(msg))+" "), msg...)
	}
	return append(msg, '\n')
}

// writeOnce connects if needed and writes one framed event.
func (s *sinkWorker) writeOnce(msg []byte, deadline time.Time) error {
	switch s.ep.scheme {
	case "file":
		if s.file == nil {
			f, err := os.OpenFile(s.ep.target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // operator-configured sink path
			if err != nil {
				return err
			}
			s.file = f
		}
		if _, err := s.file.Write(append(msg, '\n')); err != nil {
			_ = s.file.Close()
			s.file = nil
			return err
		}
		return nil

	case "udp":
		if s.conn == nil {
			conn, err := dialNet("udp", s.ep.target)
			if err != nil {
				return err
			}
			s.conn = conn
		}
		_ = s.conn.SetWriteDeadline(deadline)
		_, err := s.conn.Write(msg) // one datagram per event, unframed
		if err != nil {
			s.closeConn()
		}
		return err

	case "uds":
		if s.conn == nil {
			conn, err := dialUnixAny(s.ep.target)
			if err != nil {
				return err
			}
			s.conn = conn
		}
		_ = s.conn.SetWriteDeadline(deadline)
		var err error
		if s.conn.LocalAddr().Network() == "unixgram" {
			_, err = s.conn.Write(msg) // datagram: unframed
		} else {
			_, err = s.conn.Write(s.frame(msg))
		}
		if err != nil {
			s.closeConn()
		}
		return err

	case "tcp", "tls":
		if s.conn == nil {
			conn, err := s.dialStream()
			if err != nil {
				return err
			}
			s.conn = conn
		}
		_ = s.conn.SetWriteDeadline(deadline)
		_, err := s.conn.Write(s.frame(msg))
		if err != nil {
			s.closeConn()
		}
		return err
	default:
		return fmt.Errorf("siem: unsupported scheme %q", s.ep.scheme)
	}
}

// dialNet dials with the transport timeout. Connections are long-lived and
// owned by the worker loop; a request context does not apply here, so the
// timeout is the bound.
func dialNet(network, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	d := &net.Dialer{}
	return d.DialContext(ctx, network, target)
}

// dialStream connects tcp or tls with ServerName verification (never
// disabled); CAFile, when set, replaces the root pool (CA pinning).
func (s *sinkWorker) dialStream() (net.Conn, error) {
	if s.ep.scheme == "tcp" {
		return dialNet("tcp", s.ep.target)
	}
	host, _, err := net.SplitHostPort(s.ep.target)
	if err != nil {
		return nil, err
	}
	tcfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if s.caFile != "" {
		pem, err := os.ReadFile(s.caFile) //nolint:gosec // operator-configured CA bundle path
		if err != nil {
			return nil, fmt.Errorf("siem: read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("siem: ca_file %s contains no usable certificates", s.caFile)
		}
		tcfg.RootCAs = pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	td := &tls.Dialer{NetDialer: &net.Dialer{}, Config: tcfg}
	return td.DialContext(ctx, "tcp", s.ep.target)
}

// dialUnixAny connects a unix socket path: stream first, datagram fallback.
func dialUnixAny(path string) (net.Conn, error) {
	conn, err := dialNet("unix", path)
	if err == nil {
		return conn, nil
	}
	gconn, gerr := dialNet("unixgram", path)
	if gerr == nil {
		return gconn, nil
	}
	return nil, fmt.Errorf("siem: unix dial failed (stream: %v; datagram: %v)", err, gerr)
}

func (s *sinkWorker) closeConn() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
}
