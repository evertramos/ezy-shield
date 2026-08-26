package dashboard

// GET /metrics (issue #183): Prometheus text exposition, proxied from the
// daemon's "metrics" socket verb so the counters live in the process that
// actually does the work, and served on the EXISTING loopback listener —
// no new network listener, per the project rule.

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// metricsThrottle is a small fixed-window limiter for the /metrics route.
// The listener is loopback-only and Prometheus scrapes every 15–60s, so the
// cap is generous; it exists to bound a runaway local scraper, mirroring
// the login throttle's intent.
type metricsThrottle struct {
	mu      sync.Mutex
	window  time.Time
	count   int
	max     int
	perSpan time.Duration
}

func newMetricsThrottle() *metricsThrottle {
	return &metricsThrottle{max: 120, perSpan: time.Minute}
}

// allow reports whether one more scrape fits the current window.
func (t *metricsThrottle) allow(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.window) >= t.perSpan {
		t.window = now
		t.count = 0
	}
	t.count++
	return t.count <= t.max
}

// handleMetrics serves the exposition. Auth is decided at route
// registration (see routes): session auth by default, open when
// cfg.MetricsOpen — documented as safe only because the listener is
// loopback-only. The throttle applies on both paths.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.metricsLimit.allow(time.Now()) {
		http.Error(w, "throttled", http.StatusTooManyRequests)
		return
	}
	resp, err := s.callDaemon(r.Context(), daemon.SocketRequest{Verb: "metrics"})
	if err != nil {
		http.Error(w, "daemon unavailable", http.StatusServiceUnavailable)
		return
	}
	var data daemon.MetricsData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		http.Error(w, "bad metrics payload", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(data.Text))
}
