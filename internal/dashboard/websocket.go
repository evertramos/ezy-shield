package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

const (
	// wsPingInterval keeps NAT / proxy paths hot and lets the server
	// detect dead peers quickly. 30 s is well inside the default socket
	// timeouts of every reverse proxy an operator is likely to run.
	wsPingInterval = 30 * time.Second

	// wsWriteTimeout caps each write; a stuck client is dropped instead
	// of blocking the writer goroutine forever.
	wsWriteTimeout = 5 * time.Second
)

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Origin check: coder/websocket defaults to same-origin. The
	// dashboard is bound to loopback, so any legitimate browser tab
	// hitting this route already carries a matching Origin.
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		s.logger.Debug("websocket accept", "err", err)
		return
	}
	// Best-effort close; the exact status is derived from ctx below.
	defer func() { _ = c.CloseNow() }() //nolint:errcheck // best-effort on handler exit

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	client := s.bus.subscribe()
	defer s.bus.unsubscribe(client)

	// Send a hello message so the browser knows the socket is live even
	// before the first audit event lands.
	if hello, err := json.Marshal(wsMessage{Type: "hello"}); err == nil {
		writeCtx, writeCancel := context.WithTimeout(ctx, wsWriteTimeout)
		_ = c.Write(writeCtx, websocket.MessageText, hello)
		writeCancel()
	}

	// Reader goroutine: we don't consume client messages in Phase 3,
	// but we still need to read so control frames (ping/pong) are
	// processed by the library. A parse error → connection close.
	go func() {
		defer cancel()
		for {
			if _, _, err := c.Reader(ctx); err != nil {
				return
			}
		}
	}()

	ping := time.NewTicker(wsPingInterval)
	defer ping.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			pingCtx, pingCancel := context.WithTimeout(ctx, wsWriteTimeout)
			err := c.Ping(pingCtx)
			pingCancel()
			if err != nil {
				return
			}
		case msg, ok := <-client.send:
			if !ok {
				return
			}
			writeCtx, writeCancel := context.WithTimeout(ctx, wsWriteTimeout)
			err := c.Write(writeCtx, websocket.MessageText, msg)
			writeCancel()
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				s.logger.Debug("websocket write", "err", err)
				return
			}
		}
	}
}
