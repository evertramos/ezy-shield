// SPDX-License-Identifier: AGPL-3.0-only

// Package plugin implements the tier-1 plugin process runtime (issue
// #206): executable plugins speaking JSON over stdio. This file is the
// process-management core — spawn, handshake, request/response, timeouts,
// hard kill, restart backoff, circuit breaker. No plugin types (parser/
// notifier bridges) live here; manifest/discovery is issue #207.
//
// Wire format (recorded decision, per the public architecture): LINE-
// DELIMITED JSON — one compact JSON object per '\n'-terminated line, on
// stdin (daemon→plugin) and stdout (plugin→daemon). It matches every
// existing EzyShield protocol surface (control socket, enforcer socket),
// is trivially implementable from any language, and lets the reader
// enforce the response size cap while reading (a length prefix would let
// a hostile plugin pre-declare a huge frame).
//
// Security posture: plugin stdout is HOSTILE data. Responses are decoded
// with encoding/json into fixed shapes (unknown fields ignored), read
// through a hard 1 MiB cap, and error strings are length-capped before
// they reach logs. stderr is never parsed as protocol — it goes to a
// size-capped ring buffer surfaced only in failure logs. A hung plugin is
// SIGKILLed as a whole process group so it cannot orphan children.
package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// ProtocolVersion is the tier-1 stdio protocol version this daemon
	// speaks. A plugin answering a different version is disabled.
	ProtocolVersion = 1

	// DefaultRequestTimeout bounds one request/response round trip.
	DefaultRequestTimeout = 5 * time.Second
	// MaxRequestTimeout is the hard cap a manifest may raise the timeout
	// to (issue #207 wires the manifest override).
	MaxRequestTimeout = 30 * time.Second
	// handshakeTimeout bounds the initial handshake exchange.
	handshakeTimeout = 5 * time.Second

	// MaxResponseBytes caps one response line. Enforced WHILE reading —
	// a plugin that streams forever is cut off and killed.
	MaxResponseBytes = 1 << 20
	// maxErrorChars caps plugin-supplied error strings before logging.
	maxErrorChars = 256
	// stderrRingCap bounds the captured stderr per plugin process.
	stderrRingCap = 16 * 1024

	// defaultQueueCap bounds pending requests. A slow plugin never blocks
	// the caller: a full queue drops the request with ErrBusy + a counter.
	defaultQueueCap = 64

	// maxFailuresPerHour trips the circuit breaker: this many process
	// failures (crash, hang, protocol garbage) inside one hour disables
	// the plugin permanently (until daemon restart), audited.
	maxFailuresPerHour = 5
)

// restartBackoff is the exponential restart schedule after a failure;
// the last value repeats.
var restartBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}

// Sentinel errors callers branch on.
var (
	// ErrDisabled: the circuit breaker tripped (or the handshake was
	// rejected); the plugin will not run again this daemon lifetime.
	ErrDisabled = errors.New("plugin: disabled")
	// ErrBusy: the bounded queue is full; the request was dropped so the
	// pipeline never blocks on a slow plugin.
	ErrBusy = errors.New("plugin: queue full, request dropped")
)

// HandshakeRequest is the first line the daemon writes.
type HandshakeRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	PluginType      string `json:"plugin_type"`
}

// HandshakeResponse is the first line the plugin must answer with.
type HandshakeResponse struct {
	ProtocolVersion int      `json:"protocol_version"`
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Capabilities    []string `json:"capabilities"`
}

// request is one daemon→plugin call frame.
type request struct {
	ID      uint64          `json:"id"`
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// response is one plugin→daemon answer frame. Hostile data: decoded into
// this fixed shape, unknown fields ignored, Error length-capped on use.
type response struct {
	ID     uint64          `json:"id"`
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Config configures one plugin runtime.
type Config struct {
	// Path is the plugin executable (absolute; manifest resolution is
	// #207's job). Args are optional extra arguments.
	Path string
	Args []string
	// Type is the expected plugin_type announced in the handshake
	// ("parser", "notifier", ...).
	Type string
	// RequestTimeout bounds one round trip; zero means
	// DefaultRequestTimeout, values above MaxRequestTimeout are clamped.
	RequestTimeout time.Duration
	// QueueCap bounds pending requests (default defaultQueueCap).
	QueueCap int
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Audit, when set, receives one (op, reason) per lifecycle event the
	// operator must be able to reconstruct: restarts, breaker trips,
	// kills. The daemon wires this to its append-only audit journal.
	Audit func(op, reason string)
}

// Runtime supervises one plugin executable: a single worker goroutine
// owns the process, restarts it with backoff, and serves queued requests
// serially (the stdio protocol is strictly request/response).
type Runtime struct {
	cfg     Config
	logger  *slog.Logger
	timeout time.Duration
	// backoff is the restart schedule (copied from restartBackoff;
	// shortened in tests).
	backoff []time.Duration

	queue   chan *pending
	dropped atomic.Uint64

	mu           sync.Mutex
	disabled     bool
	disabledWhy  string
	failures     []time.Time // failure timestamps inside the breaker window
	restartCount int

	// handshake result, set once the first process comes up.
	hsMu sync.Mutex
	hs   *HandshakeResponse

	started atomic.Bool
	done    chan struct{}
	nextID  atomic.Uint64
}

// pending is one queued call.
type pending struct {
	ctx     context.Context
	method  string
	payload json.RawMessage
	result  chan callResult
}

type callResult struct {
	raw json.RawMessage
	err error
}

// NewRuntime validates and prepares a runtime; Start launches it.
func NewRuntime(cfg Config) *Runtime {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	if timeout > MaxRequestTimeout {
		timeout = MaxRequestTimeout
	}
	qcap := cfg.QueueCap
	if qcap <= 0 {
		qcap = defaultQueueCap
	}
	return &Runtime{
		cfg:     cfg,
		logger:  cfg.Logger.With("plugin_exec", cfg.Path, "plugin_type", cfg.Type),
		timeout: timeout,
		backoff: restartBackoff,
		queue:   make(chan *pending, qcap),
		done:    make(chan struct{}),
	}
}

// Start runs the supervisor until ctx is cancelled. It returns after the
// worker goroutine is launched; cancellation kills the plugin process
// group and drains the queue with errors.
func (r *Runtime) Start(ctx context.Context) {
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	go r.supervise(ctx)
}

// Handshake returns the plugin's announced identity once available.
func (r *Runtime) Handshake() (HandshakeResponse, bool) {
	r.hsMu.Lock()
	defer r.hsMu.Unlock()
	if r.hs == nil {
		return HandshakeResponse{}, false
	}
	return *r.hs, true
}

// Dropped reports how many requests were dropped by the bounded queue.
func (r *Runtime) Dropped() uint64 { return r.dropped.Load() }

// Disabled reports whether the circuit breaker (or handshake rejection)
// permanently disabled this plugin.
func (r *Runtime) Disabled() (bool, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.disabled, r.disabledWhy
}

// Call sends one request and waits for its response, the per-request
// timeout, or ctx. A full queue returns ErrBusy immediately — a slow
// plugin never blocks the calling pipeline.
func (r *Runtime) Call(ctx context.Context, method string, payload json.RawMessage) (json.RawMessage, error) {
	if disabled, why := r.Disabled(); disabled {
		return nil, fmt.Errorf("%w: %s", ErrDisabled, why)
	}
	p := &pending{ctx: ctx, method: method, payload: payload, result: make(chan callResult, 1)}
	select {
	case r.queue <- p:
	default:
		n := r.dropped.Add(1)
		r.logger.Warn("plugin: queue full; request dropped", "method", method, "dropped_total", n)
		return nil, ErrBusy
	}
	select {
	case res := <-p.result:
		return res.raw, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.done:
		return nil, fmt.Errorf("plugin: runtime stopped")
	}
}

// supervise is the worker: owns the process, restarts on failure with
// exponential backoff, trips the breaker on repeated failures, and kills
// everything on ctx cancellation.
func (r *Runtime) supervise(ctx context.Context) {
	defer close(r.done)
	for {
		if ctx.Err() != nil {
			return
		}
		if disabled, _ := r.Disabled(); disabled {
			r.drainDisabled(ctx)
			return
		}

		proc, hs, err := startProcess(ctx, r.cfg, r.logger)
		if err != nil {
			if errors.Is(err, errHandshakeRejected) {
				// Version/type mismatch is permanent: retrying cannot fix
				// a wrong protocol. Disable with a clear log; the daemon
				// is unaffected.
				r.disable("handshake rejected: " + err.Error())
				continue
			}
			if !r.recordFailure(ctx, "start failed: "+err.Error()) {
				continue
			}
			continue
		}
		r.hsMu.Lock()
		r.hs = hs
		r.hsMu.Unlock()
		r.logger.Info("plugin: up", "name", hs.Name, "version", hs.Version)

		// Serve requests until the process misbehaves or ctx ends.
		serveErr := r.serve(ctx, proc)
		proc.kill()
		if ctx.Err() != nil {
			return
		}
		if !r.recordFailure(ctx, serveErr.Error()) {
			continue
		}
	}
}

// serve pumps queued requests through one live process. Returns the error
// that ended the process's usefulness (never nil).
func (r *Runtime) serve(ctx context.Context, proc *process) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-proc.exited:
			return fmt.Errorf("process exited (stderr: %s)", proc.stderrTail())
		case p := <-r.queue:
			if p.ctx.Err() != nil {
				p.result <- callResult{err: p.ctx.Err()}
				continue
			}
			raw, err := r.roundTrip(p, proc)
			p.result <- callResult{raw: raw, err: err}
			if err != nil && isProcessFatal(err) {
				return err
			}
		}
	}
}

// roundTrip performs one write→read exchange with the per-request
// timeout. A timeout is fatal for the process (it is hung mid-protocol):
// the caller kills the process group.
func (r *Runtime) roundTrip(p *pending, proc *process) (json.RawMessage, error) {
	id := r.nextID.Add(1)
	req := request{ID: id, Method: p.method, Payload: p.payload}
	deadline := time.Now().Add(r.timeout)

	if err := proc.writeLine(req, deadline); err != nil {
		return nil, &procError{fmt.Errorf("write: %w", err)}
	}
	line, err := proc.readLine(deadline)
	if err != nil {
		return nil, &procError{fmt.Errorf("read: %w (stderr: %s)", err, proc.stderrTail())}
	}
	var resp response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, &procError{fmt.Errorf("malformed response: %w", err)}
	}
	if resp.ID != id {
		return nil, &procError{fmt.Errorf("response id %d does not match request %d", resp.ID, id)}
	}
	if !resp.OK {
		// A structured error is a HEALTHY protocol exchange — the plugin
		// declined this request; the process keeps serving.
		return nil, fmt.Errorf("plugin error: %s", capString(resp.Error, maxErrorChars))
	}
	return resp.Result, nil
}

// procError marks errors that invalidate the process itself.
type procError struct{ err error }

func (e *procError) Error() string { return e.err.Error() }
func (e *procError) Unwrap() error { return e.err }

func isProcessFatal(err error) bool {
	var pe *procError
	return errors.As(err, &pe)
}

// recordFailure counts one failure inside the breaker window, waits the
// restart backoff (honoring ctx), and reports whether the caller should
// KEEP GOING (false means it should re-check disabled state). Trips the
// breaker at maxFailuresPerHour.
func (r *Runtime) recordFailure(ctx context.Context, why string) bool {
	r.mu.Lock()
	now := time.Now()
	cutoff := now.Add(-time.Hour)
	kept := r.failures[:0]
	for _, t := range r.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.failures = append(kept, now)
	count := len(r.failures)
	r.restartCount++
	attempt := r.restartCount
	r.mu.Unlock()

	r.logger.Warn("plugin: process failure", "reason", capString(why, maxErrorChars), "failures_last_hour", count)
	r.audit("plugin_restart", fmt.Sprintf("exec=%s failures_last_hour=%d reason=%s", r.cfg.Path, count, capString(why, maxErrorChars)))

	if count >= maxFailuresPerHour {
		r.disable(fmt.Sprintf("%d failures within one hour", count))
		return false
	}

	idx := attempt - 1
	if idx >= len(r.backoff) {
		idx = len(r.backoff) - 1
	}
	select {
	case <-ctx.Done():
	case <-time.After(r.backoff[idx]):
	}
	return true
}

// disable trips the circuit breaker permanently (this daemon lifetime).
func (r *Runtime) disable(why string) {
	r.mu.Lock()
	already := r.disabled
	if !already {
		r.disabled = true
		r.disabledWhy = why
	}
	r.mu.Unlock()
	if already {
		return
	}
	r.logger.Error("plugin: permanently disabled", "reason", why)
	r.audit("plugin_disabled", fmt.Sprintf("exec=%s reason=%s", r.cfg.Path, capString(why, maxErrorChars)))
}

// drainDisabled answers queued and future requests with ErrDisabled until
// ctx ends, so callers never hang on a dead plugin.
func (r *Runtime) drainDisabled(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-r.queue:
			p.result <- callResult{err: ErrDisabled}
		}
	}
}

func (r *Runtime) audit(op, reason string) {
	if r.cfg.Audit != nil {
		r.cfg.Audit(op, reason)
	}
}

// ── Process ──────────────────────────────────────────────────────────────────

// process is one live plugin subprocess with its pipes and stderr ring.
type process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	logger *slog.Logger

	ring *stderrRing
	// exited closes when the process has been reaped — the supervisor
	// notices a crash immediately instead of at the next request.
	exited chan struct{}

	killOnce sync.Once
}

// errHandshakeRejected marks a permanent handshake failure (version or
// type mismatch) — restarting cannot help.
var errHandshakeRejected = errors.New("handshake rejected")

// startProcess spawns the executable in its OWN PROCESS GROUP (so a hard
// kill reaps any children it spawned), wires the pipes, and performs the
// handshake.
func startProcess(ctx context.Context, cfg Config, logger *slog.Logger) (*process, *HandshakeResponse, error) {
	// The command deliberately does NOT use exec.CommandContext: ctx
	// cancellation must kill the whole process group, which the runtime
	// does itself via kill().
	cmd := exec.Command(cfg.Path, cfg.Args...) //nolint:gosec,noctx // path comes from the operator-allowlisted manifest (#207), never remote input; ctx kill is done group-wide by kill(), which CommandContext's single-process kill cannot do
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("stdout pipe: %w", err)
	}
	ring := newStderrRing(stderrRingCap)
	cmd.Stderr = ring

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start %s: %w", cfg.Path, err)
	}
	p := &process{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdout, 64*1024),
		logger: logger,
		ring:   ring,
		exited: make(chan struct{}),
	}
	// Reap the process when it exits (crash or kill) so it never zombies,
	// and signal the supervisor immediately.
	go func() {
		_ = cmd.Wait()
		close(p.exited)
	}()

	// Kill the group if ctx dies while the process lives.
	go func() {
		<-ctx.Done()
		p.kill()
	}()

	hs, err := p.handshake(cfg)
	if err != nil {
		p.kill()
		return nil, nil, err
	}
	return p, hs, nil
}

// handshake writes the daemon hello and validates the plugin's answer.
func (p *process) handshake(cfg Config) (*HandshakeResponse, error) {
	deadline := time.Now().Add(handshakeTimeout)
	if err := p.writeLine(HandshakeRequest{ProtocolVersion: ProtocolVersion, PluginType: cfg.Type}, deadline); err != nil {
		return nil, fmt.Errorf("handshake write: %w", err)
	}
	line, err := p.readLine(deadline)
	if err != nil {
		return nil, fmt.Errorf("handshake read: %w (stderr: %s)", err, p.stderrTail())
	}
	var hs HandshakeResponse
	if err := json.Unmarshal(line, &hs); err != nil {
		return nil, fmt.Errorf("handshake decode: %w", err)
	}
	if hs.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("%w: plugin speaks protocol %d, daemon speaks %d",
			errHandshakeRejected, hs.ProtocolVersion, ProtocolVersion)
	}
	if hs.Name == "" {
		return nil, fmt.Errorf("%w: plugin announced no name", errHandshakeRejected)
	}
	hs.Name = capString(hs.Name, 64)
	hs.Version = capString(hs.Version, 64)
	for i, c := range hs.Capabilities {
		hs.Capabilities[i] = capString(c, 64)
	}
	return &hs, nil
}

// writeLine marshals v and writes one '\n'-terminated line before the
// deadline (enforced by a watchdog kill — pipes have no deadlines).
func (p *process) writeLine(v any, deadline time.Time) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	done := make(chan struct{})
	timer := time.AfterFunc(time.Until(deadline), func() {
		select {
		case <-done:
		default:
			p.kill() // unblocks the Write with EPIPE
		}
	})
	defer timer.Stop()
	_, err = p.stdin.Write(data)
	close(done)
	return err
}

// readLine reads one line, enforcing MaxResponseBytes WHILE reading and
// the deadline via a watchdog kill (a hung plugin gets SIGKILL to its
// whole group, which unblocks the Read).
func (p *process) readLine(deadline time.Time) ([]byte, error) {
	// Watchdog kill, not a goroutine leak: the blocked Read unblocks the
	// moment the process group dies.
	var timedOut atomic.Bool
	timer := time.AfterFunc(time.Until(deadline), func() {
		timedOut.Store(true)
		p.kill()
	})
	defer timer.Stop()

	var buf []byte
	for {
		chunk, err := p.stdout.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > MaxResponseBytes {
			p.kill()
			return nil, fmt.Errorf("response exceeds %d bytes", MaxResponseBytes)
		}
		if err == nil {
			return buf[:len(buf)-1], nil // strip '\n'
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if timedOut.Load() {
			return nil, fmt.Errorf("request timeout (process group killed)")
		}
		return nil, err
	}
}

// kill SIGKILLs the whole process group exactly once.
func (p *process) kill() {
	p.killOnce.Do(func() {
		if p.cmd.Process == nil {
			return
		}
		pid := p.cmd.Process.Pid
		// Negative pid = the whole group (Setpgid put the plugin and any
		// children it spawned into their own group).
		if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
			_ = p.cmd.Process.Kill()
		}
		_ = p.stdin.Close()
	})
}

// stderrTail renders the captured stderr tail for failure logs — never
// parsed as protocol, only surfaced to the operator, capped.
func (p *process) stderrTail() string {
	return capString(p.ring.String(), maxErrorChars)
}

// capString truncates s to max runes-safe bytes for logs.
func capString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// ── stderr ring buffer ───────────────────────────────────────────────────────

// stderrRing keeps the LAST cap bytes written (a hostile plugin cannot
// grow daemon memory by spewing stderr).
type stderrRing struct {
	mu  sync.Mutex
	buf []byte
	cap int
}

func newStderrRing(capBytes int) *stderrRing {
	return &stderrRing{cap: capBytes}
}

func (r *stderrRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.cap {
		r.buf = r.buf[len(r.buf)-r.cap:]
	}
	return len(p), nil
}

func (r *stderrRing) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.buf)
}
