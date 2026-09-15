// SPDX-License-Identifier: AGPL-3.0-only

package collector_test

// Endpoint parsing and transport selection for docker.host (issue #579).
// The tcp variant is an attacker-adjacent network peer, so the transport
// assertions here are security assertions: the dial target can never be
// steered by a URL, no proxy is inherited from the environment, and no
// redirect is ever followed.

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/collector"
)

func TestParseDockerHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		raw        string
		wantErr    bool
		wantScheme string
		wantTarget string // SocketPath for unix, Address for tcp
		wantLocal  bool
	}{
		{name: "empty means the default socket", raw: "",
			wantScheme: "unix", wantTarget: "/var/run/docker.sock", wantLocal: true},
		{name: "default unix socket", raw: "unix:///var/run/docker.sock",
			wantScheme: "unix", wantTarget: "/var/run/docker.sock", wantLocal: true},
		{name: "custom unix socket", raw: "unix:///run/user/1000/docker.sock",
			wantScheme: "unix", wantTarget: "/run/user/1000/docker.sock", wantLocal: true},
		{name: "unix path is cleaned", raw: "unix:///var/run/../run/docker.sock",
			wantScheme: "unix", wantTarget: "/var/run/docker.sock", wantLocal: true},
		{name: "tcp loopback v4", raw: "tcp://127.0.0.1:2375",
			wantScheme: "tcp", wantTarget: "127.0.0.1:2375", wantLocal: true},
		{name: "tcp loopback v4 non-canonical", raw: "tcp://127.0.0.53:2375",
			wantScheme: "tcp", wantTarget: "127.0.0.53:2375", wantLocal: true},
		{name: "tcp loopback v6", raw: "tcp://[::1]:2375",
			wantScheme: "tcp", wantTarget: "[::1]:2375", wantLocal: true},
		{name: "tcp trailing slash", raw: "tcp://127.0.0.1:2375/",
			wantScheme: "tcp", wantTarget: "127.0.0.1:2375", wantLocal: true},
		// Parsing accepts a routable host; the loopback rule is a policy
		// decision the config layer makes on top (docker.allow_remote).
		{name: "tcp non-loopback parses but is not local", raw: "tcp://192.0.2.10:2375",
			wantScheme: "tcp", wantTarget: "192.0.2.10:2375", wantLocal: false},
		{name: "tcp v6 documentation range is not local", raw: "tcp://[2001:db8::1]:2375",
			wantScheme: "tcp", wantTarget: "[2001:db8::1]:2375", wantLocal: false},
		// A NAME is never treated as loopback: what it resolves to is decided
		// by /etc/hosts and DNS, not by the operator's config.
		{name: "tcp localhost name is not proven loopback", raw: "tcp://localhost:2375",
			wantScheme: "tcp", wantTarget: "localhost:2375", wantLocal: false},

		{name: "relative unix path", raw: "unix://var/run/docker.sock", wantErr: true},
		{name: "unix with query", raw: "unix:///var/run/docker.sock?x=1", wantErr: true},
		{name: "tcp without port", raw: "tcp://127.0.0.1", wantErr: true},
		{name: "tcp without host", raw: "tcp://:2375", wantErr: true},
		{name: "tcp with path", raw: "tcp://127.0.0.1:2375/containers", wantErr: true},
		{name: "tcp port not a number", raw: "tcp://127.0.0.1:docker", wantErr: true},
		{name: "tcp port out of range", raw: "tcp://127.0.0.1:70000", wantErr: true},
		{name: "no scheme", raw: "/var/run/docker.sock", wantErr: true},
		{name: "bare host:port", raw: "127.0.0.1:2375", wantErr: true},
		{name: "http scheme", raw: "http://127.0.0.1:2375", wantErr: true},
		{name: "https scheme", raw: "https://127.0.0.1:2376", wantErr: true},
		{name: "ssh scheme", raw: "ssh://docker@192.0.2.10", wantErr: true},
		{name: "npipe scheme", raw: "npipe:////./pipe/docker_engine", wantErr: true},
		// A value that looks like a secret is refused, never silently dropped.
		//nolint:gosec // G101: the point of this case is that a credential-shaped endpoint is rejected
		{name: "tcp with userinfo", raw: "tcp://testuser:notasecret@127.0.0.1:2375", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ep, err := collector.ParseDockerHost(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseDockerHost(%q) = %+v, want an error", tc.raw, ep)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDockerHost(%q): %v", tc.raw, err)
			}
			if ep.Scheme != tc.wantScheme {
				t.Errorf("scheme = %q, want %q", ep.Scheme, tc.wantScheme)
			}
			got := ep.SocketPath
			if ep.IsTCP() {
				got = ep.Address
			}
			if got != tc.wantTarget {
				t.Errorf("target = %q, want %q", got, tc.wantTarget)
			}
			if ep.IsLoopback() != tc.wantLocal {
				t.Errorf("IsLoopback() = %v, want %v", ep.IsLoopback(), tc.wantLocal)
			}
		})
	}
}

// TestDockerEndpointURL checks the request URL carries the real target host
// for tcp (so the Host header is truthful) and the historical placeholder for
// unix (where the host is meaningless).
func TestDockerEndpointURL(t *testing.T) {
	t.Parallel()

	unix, err := collector.ParseDockerHost("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatalf("parse unix: %v", err)
	}
	if got, want := unix.URL("/_ping"), "http://docker/_ping"; got != want {
		t.Errorf("unix URL = %q, want %q", got, want)
	}
	if got, want := unix.String(), "unix:///var/run/docker.sock"; got != want {
		t.Errorf("unix String = %q, want %q", got, want)
	}

	tcp, err := collector.ParseDockerHost("tcp://127.0.0.1:2375")
	if err != nil {
		t.Fatalf("parse tcp: %v", err)
	}
	if got, want := tcp.URL("/_ping"), "http://127.0.0.1:2375/_ping"; got != want {
		t.Errorf("tcp URL = %q, want %q", got, want)
	}
	if got, want := tcp.String(), "tcp://127.0.0.1:2375"; got != want {
		t.Errorf("tcp String = %q, want %q", got, want)
	}
}

// startUnixEcho serves a fixed body on a unix socket and returns its path.
func startUnixEcho(t *testing.T, body string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// TestNewDockerAPIClient_TransportSelection is the transport table: the client
// built for an endpoint reaches THAT endpoint, and the host in the request URL
// never decides where the bytes go.
func TestNewDockerAPIClient_TransportSelection(t *testing.T) {
	t.Parallel()

	tcpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tcp-endpoint"))
	}))
	t.Cleanup(tcpSrv.Close)
	unixSock := startUnixEcho(t, "unix-endpoint")

	tests := []struct {
		name string
		host string
		// url is deliberately pointed at a host that does not exist: the
		// transport must ignore it entirely.
		url  string
		want string
	}{
		{name: "unix endpoint", host: "unix://" + unixSock, url: "http://docker/_ping", want: "unix-endpoint"},
		{name: "unix endpoint ignores URL host", host: "unix://" + unixSock,
			url: "http://192.0.2.10:2375/_ping", want: "unix-endpoint"},
		{name: "tcp endpoint", host: "tcp://" + tcpSrv.Listener.Addr().String(),
			url: "http://docker/_ping", want: "tcp-endpoint"},
		{name: "tcp endpoint ignores URL host", host: "tcp://" + tcpSrv.Listener.Addr().String(),
			url: "http://198.51.100.7:9999/_ping", want: "tcp-endpoint"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ep, err := collector.ParseDockerHost(tc.host)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.host, err)
			}
			client := collector.NewDockerAPIClient(ep)
			defer client.CloseIdleConnections()

			if got := doGet(t, client, tc.url); got != tc.want {
				t.Errorf("body = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNewDockerAPIClient_NoRedirectFollowed: a hostile or misconfigured proxy
// must not be able to bounce this client anywhere. The redirect is surfaced as
// the response itself, so the caller fails on the non-200 status.
func TestNewDockerAPIClient_NoRedirectFollowed(t *testing.T) {
	t.Parallel()

	var followed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed = true
			_, _ = w.Write([]byte("should never be reached"))
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	ep, err := collector.ParseDockerHost("tcp://" + srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	client := collector.NewDockerAPIClient(ep)
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ep.URL("/_ping"), nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (redirect returned, not followed)", resp.StatusCode, http.StatusFound)
	}
	if followed {
		t.Error("client followed the redirect; a Docker endpoint must never be able to steer it")
	}
}

// TestNewDockerAPIClient_IgnoresEnvProxy: the Docker API is a host-local trust
// boundary. An HTTP_PROXY in the daemon's environment must not route Engine
// traffic (and its container log content) through a third party.
func TestNewDockerAPIClient_IgnoresEnvProxy(t *testing.T) {
	// Not parallel: mutates process environment.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("direct"))
	}))
	t.Cleanup(srv.Close)

	// A proxy that would fail loudly if it were ever consulted.
	t.Setenv("HTTP_PROXY", "http://192.0.2.99:3128")
	t.Setenv("http_proxy", "http://192.0.2.99:3128")

	ep, err := collector.ParseDockerHost("tcp://" + srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	client := collector.NewDockerAPIClient(ep)
	defer client.CloseIdleConnections()

	if got := doGet(t, client, ep.URL("/_ping")); got != "direct" {
		t.Errorf("body = %q, want %q (env proxy must be ignored)", got, "direct")
	}
}

func doGet(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request %s: %v", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}
