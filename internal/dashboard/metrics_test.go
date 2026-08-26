// SPDX-License-Identifier: AGPL-3.0-only

package dashboard

// Tests for GET /metrics (issue #183): auth on/off behavior, throttle, and
// the daemon proxy path.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

const testExposition = "# HELP ezyshield_build_info Build information; the value is always 1.\n" +
	"# TYPE ezyshield_build_info gauge\n" +
	"ezyshield_build_info{version=\"test\"} 1\n"

// fakeMetricsDaemon serves the daemon socket protocol answering the
// "metrics" verb with a canned exposition.
func fakeMetricsDaemon(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "daemon.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
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
			go func(conn net.Conn) {
				defer conn.Close() //nolint:errcheck
				var req daemon.SocketRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				data, _ := json.Marshal(daemon.MetricsData{Text: testExposition})
				resp := daemon.SocketResponse{OK: req.Verb == "metrics", Data: data}
				_ = json.NewEncoder(conn).Encode(resp)
			}(conn)
		}
	}()
	return sock
}

// newMetricsTestServer builds a dashboard wired to a fake daemon socket.
func newMetricsTestServer(t *testing.T, open bool) (*http.Client, string) {
	t.Helper()
	dir := t.TempDir()
	srv, err := New(Config{
		Addr:             "127.0.0.1:0",
		AuthDBPath:       filepath.Join(dir, "dashboard.db"),
		DaemonSocketPath: fakeMetricsDaemon(t),
		MetricsOpen:      open,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hash, err := hashPassword("metrics-test-pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.store.setAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(srv.Handler())
	jar, _ := cookiejar.New(nil)
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	t.Cleanup(func() {
		ts.Close()
		_ = srv.Close()
	})
	return client, ts.URL
}

func TestMetrics_AuthRequiredByDefault(t *testing.T) {
	client, base := newMetricsTestServer(t, false)

	// Unauthenticated scrape is redirected to login, never served.
	resp := doGet(t, client, base+"/metrics")
	closeBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("unauth /metrics status = %d, want a redirect to /login", resp.StatusCode)
	}

	// After login the same client scrapes fine.
	login := doPostForm(t, client, base+"/login", url.Values{
		"username": {"admin"}, "password": {"metrics-test-pw"},
	})
	closeBody(t, login)
	resp = doGet(t, client, base+"/metrics")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authed /metrics status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "ezyshield_build_info") {
		t.Errorf("body = %q, want exposition", string(body))
	}
}

func TestMetrics_OpenMode(t *testing.T) {
	client, base := newMetricsTestServer(t, true)
	resp := doGet(t, client, base+"/metrics")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("open /metrics status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "version=0.0.4") {
		t.Errorf("content-type = %q, want the prometheus text format", ct)
	}
	if !strings.Contains(string(body), `version="test"`) {
		t.Errorf("body = %q", string(body))
	}
}

func TestMetrics_Throttled(t *testing.T) {
	client, base := newMetricsTestServer(t, true)
	throttled := false
	for i := 0; i < 150; i++ {
		resp := doGet(t, client, base+"/metrics")
		if resp.StatusCode == http.StatusTooManyRequests {
			throttled = true
		}
		closeBody(t, resp)
	}
	if !throttled {
		t.Fatal("150 rapid scrapes never hit the throttle")
	}
}
