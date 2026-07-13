package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// DefaultDialTimeout is the maximum time Call waits for the unix socket to
// accept the connection. Callers that need a tighter budget (e.g. dashboard
// pages that must render promptly when the daemon is offline) can wrap Call
// with a shorter context.
const DefaultDialTimeout = 5 * time.Second

// ErrDaemonUnreachable is returned by Call when the unix socket refuses the
// connection — either the daemon is not running, the socket path is wrong,
// or the calling user is not in the ezyshield group. Callers can errors.Is
// against this to render a graceful "daemon offline" state instead of a raw
// syscall error.
var ErrDaemonUnreachable = errors.New("daemon unreachable")

// Call opens a connection to the daemon unix socket, sends req as a single
// newline-terminated JSON object, and returns the decoded response.
//
// The dial phase respects ctx and DefaultDialTimeout (whichever fires first).
// A refused connection is wrapped as ErrDaemonUnreachable so callers can
// distinguish "the daemon is down" from "the daemon returned an error".
// A non-OK response from a reachable daemon is returned alongside a non-nil
// error whose Error() is resp.Error, giving callers the option to still
// inspect the payload.
func Call(ctx context.Context, socketPath string, req SocketRequest) (*SocketResponse, error) {
	dialer := &net.Dialer{Timeout: DefaultDialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrDaemonUnreachable, socketPath, err)
	}
	defer conn.Close() //nolint:errcheck // best-effort close on RPC completion

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("daemon: send %q: %w", req.Verb, err)
	}

	var resp SocketResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("daemon: read %q response: %w", req.Verb, err)
	}
	if !resp.OK {
		return &resp, fmt.Errorf("daemon %q: %s", req.Verb, resp.Error)
	}
	return &resp, nil
}

// Subscribe opens a long-lived "subscribe" connection to the daemon socket
// and invokes onEvent for every StreamEvent the daemon pushes. connected (if
// non-nil) is called once, after the daemon acknowledges the subscription —
// callers use it to reset reconnect backoff and to distinguish "never got
// through" from "stream dropped".
//
// Subscribe blocks. It returns nil when ctx is cancelled, ErrDaemonUnreachable
// when the socket refuses the connection, and a descriptive error when an
// established stream drops (daemon restart) so callers can reconnect.
func Subscribe(ctx context.Context, socketPath string, connected func(), onEvent func(StreamEvent)) error {
	dialer := &net.Dialer{Timeout: DefaultDialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrDaemonUnreachable, socketPath, err)
	}
	defer conn.Close() //nolint:errcheck // best-effort close when the stream ends

	// Close the connection when ctx is cancelled so the blocking Decode below
	// unblocks promptly (clean SIGINT exit for `watch`).
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if err := json.NewEncoder(conn).Encode(SocketRequest{Verb: "subscribe"}); err != nil {
		return fmt.Errorf("daemon: send \"subscribe\": %w", err)
	}

	dec := json.NewDecoder(conn)
	var ack SocketResponse
	if err := dec.Decode(&ack); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("daemon: read \"subscribe\" ack: %w", err)
	}
	if !ack.OK {
		return fmt.Errorf("daemon \"subscribe\": %s", ack.Error)
	}
	if connected != nil {
		connected()
	}

	for {
		var ev StreamEvent
		if err := dec.Decode(&ev); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("daemon: event stream closed: %w", err)
		}
		onEvent(ev)
	}
}
