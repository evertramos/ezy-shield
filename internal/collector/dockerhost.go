// SPDX-License-Identifier: AGPL-3.0-only

package collector

// Docker Engine API endpoint resolution, shared by the streaming log
// collector (docker.go), the exec watcher (dockerexec.go), the daemon's
// on-demand evidence extraction and doctor. No build tag: the daemon and the
// CLI compile on every platform even though the collectors are linux-only.
//
// Two transports are supported:
//
//	unix:///var/run/docker.sock   the engine socket (default; the historical
//	                              behaviour). Reaching it requires membership
//	                              in the 'docker' group, which is
//	                              root-equivalent on the host.
//	tcp://127.0.0.1:2375          a filtering, read-only proxy in front of the
//	                              engine — the scoped alternative to that
//	                              group. EzyShield is only ever a client here;
//	                              it opens no listener of its own.
//
// A tcp endpoint is attacker-adjacent input: a network peer whose responses
// this process parses. Everything that reaches it is bounded accordingly —
// no proxy is inherited from the environment, no redirect is followed,
// response headers have a deadline, and response bodies never reach an error
// string (SECURITY-REVIEW.md §1).

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// DefaultDockerHost is the endpoint used when nothing is configured. It
// reproduces the behaviour of every install that predates docker.host.
const DefaultDockerHost = "unix:///var/run/docker.sock"

const (
	// dockerDialTimeout bounds establishing the connection. A tcp endpoint
	// that blackholes SYNs must not wedge a collector goroutine.
	dockerDialTimeout = 5 * time.Second
	// dockerResponseHeaderTimeout bounds how long the endpoint may take to
	// send response headers. It deliberately does NOT bound the body, so the
	// following log and event streams stay open for as long as they should.
	dockerResponseHeaderTimeout = 10 * time.Second
	// DockerRequestTimeout bounds one whole non-streaming request (_ping,
	// inspect, a doctor probe): those have a response body of known-small
	// size, so the entire exchange gets a deadline.
	DockerRequestTimeout = 10 * time.Second
)

// DockerEndpoint is a validated Docker Engine API endpoint. The zero value is
// not usable; build one with ParseDockerHost.
type DockerEndpoint struct {
	// Scheme is "unix" or "tcp".
	Scheme string
	// SocketPath is the absolute unix socket path (Scheme == "unix").
	SocketPath string
	// Address is the "host:port" dial target (Scheme == "tcp").
	Address string
}

// ParseDockerHost validates a docker.host value and returns the endpoint it
// designates. An empty string means DefaultDockerHost.
//
// Only unix:// and tcp:// are accepted. Anything else — including the ssh://
// and http(s):// forms the docker CLI understands — is refused rather than
// silently reinterpreted: this process must never be talked into speaking to
// an endpoint the operator did not describe exactly.
func ParseDockerHost(raw string) (DockerEndpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = DefaultDockerHost
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Parse errors quote the input themselves; the value is the
		// operator's own config, never log-derived data.
		return DockerEndpoint{}, fmt.Errorf("invalid docker host %q: %w", raw, err)
	}

	switch u.Scheme {
	case "unix":
		// "unix:///var/run/docker.sock" parses as Host="" Path="/var/...".
		// A host component ("unix://var/run/docker.sock") is a missing slash,
		// not an endpoint — resolving it to a relative path would be worse
		// than saying so.
		if u.Host != "" {
			return DockerEndpoint{}, fmt.Errorf(
				"invalid docker host %q: unix:// takes an absolute path and no host (unix:///var/run/docker.sock)", raw)
		}
		if !strings.HasPrefix(u.Path, "/") {
			return DockerEndpoint{}, fmt.Errorf(
				"invalid docker host %q: unix:// socket path must be absolute", raw)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return DockerEndpoint{}, fmt.Errorf(
				"invalid docker host %q: unix:// takes a plain socket path (no query or fragment)", raw)
		}
		return DockerEndpoint{Scheme: "unix", SocketPath: path.Clean(u.Path)}, nil

	case "tcp":
		// Userinfo is refused rather than dropped: the Engine API takes no
		// credentials, so "tcp://user:pass@host:2375" means the operator
		// expects an authentication that will not happen — and silently
		// discarding a value that looks like a secret is the wrong failure
		// mode (Hard Rule 3). The value itself is never echoed back.
		if u.User != nil {
			return DockerEndpoint{}, fmt.Errorf(
				"invalid docker host: credentials in a tcp:// endpoint are not supported (the Engine API takes none)")
		}
		if u.Path != "" && u.Path != "/" {
			return DockerEndpoint{}, fmt.Errorf(
				"invalid docker host %q: tcp:// takes host:port with no path (tcp://127.0.0.1:2375)", raw)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return DockerEndpoint{}, fmt.Errorf(
				"invalid docker host %q: tcp:// takes host:port only (no query or fragment)", raw)
		}
		host, port, splitErr := net.SplitHostPort(u.Host)
		if splitErr != nil {
			return DockerEndpoint{}, fmt.Errorf(
				"invalid docker host %q: tcp:// requires host:port (tcp://127.0.0.1:2375)", raw)
		}
		if host == "" {
			return DockerEndpoint{}, fmt.Errorf(
				"invalid docker host %q: tcp:// requires a host (tcp://127.0.0.1:2375)", raw)
		}
		n, portErr := strconv.Atoi(port)
		if portErr != nil || n < 1 || n > 65535 {
			return DockerEndpoint{}, fmt.Errorf(
				"invalid docker host %q: port must be a number in 1..65535", raw)
		}
		return DockerEndpoint{Scheme: "tcp", Address: net.JoinHostPort(host, port)}, nil

	case "":
		return DockerEndpoint{}, fmt.Errorf(
			"invalid docker host %q: missing scheme (use unix:///var/run/docker.sock or tcp://127.0.0.1:2375)", raw)
	default:
		return DockerEndpoint{}, fmt.Errorf(
			"invalid docker host %q: scheme %q is not supported (use unix:// or tcp://)", raw, u.Scheme)
	}
}

// IsUnix reports whether the endpoint is a unix socket.
func (e DockerEndpoint) IsUnix() bool { return e.Scheme == "unix" }

// IsTCP reports whether the endpoint is a TCP address.
func (e DockerEndpoint) IsTCP() bool { return e.Scheme == "tcp" }

// String renders the endpoint back in docker.host syntax. Endpoints carry no
// credentials, so this is safe to log.
func (e DockerEndpoint) String() string {
	switch e.Scheme {
	case "unix":
		return "unix://" + e.SocketPath
	case "tcp":
		return "tcp://" + e.Address
	default:
		return ""
	}
}

// IsLoopback reports whether the endpoint is confined to this host. A unix
// socket always is. A tcp endpoint is only accepted as loopback when its host
// is an IP LITERAL in 127.0.0.0/8 or ::1 — a name (including "localhost") is
// reported as non-loopback, because what it resolves to is decided by
// /etc/hosts and DNS, i.e. not by the operator's config. Comparison is on the
// parsed netip.Addr, never on the string.
func (e DockerEndpoint) IsLoopback() bool {
	if e.Scheme != "tcp" {
		return true
	}
	host, _, err := net.SplitHostPort(e.Address)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// URL builds an absolute Engine API request URL for apiPath (which must begin
// with "/"). The transport always dials the configured endpoint, so the host
// in the URL only decides the Host header; it is set to the real target so
// the request stays truthful about where it is going.
func (e DockerEndpoint) URL(apiPath string) string {
	host := "docker"
	if e.Scheme == "tcp" {
		host = e.Address
	}
	return "http://" + host + apiPath
}

// NewDockerAPIClient returns an http.Client bound to one Docker endpoint.
//
// The transport dials the endpoint directly and ignores the host portion of
// every request URL, so a request can never be steered somewhere else. On top
// of that:
//
//   - Proxy is nil: the Docker API is a host-local trust boundary and must
//     not be routed through whatever HTTP_PROXY a shell profile exports.
//   - Redirects are never followed: a Docker endpoint has no legitimate
//     reason to redirect, and the caller fails on the non-2xx status instead.
//   - Response headers have a deadline, so an endpoint that accepts the
//     connection and then goes silent cannot hold a goroutine forever.
func NewDockerAPIClient(ep DockerEndpoint) *http.Client {
	network, address := "unix", ep.SocketPath
	if ep.IsTCP() {
		network, address = "tcp", ep.Address
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: dockerDialTimeout}
				return d.DialContext(ctx, network, address)
			},
			ResponseHeaderTimeout: dockerResponseHeaderTimeout,
			MaxIdleConnsPerHost:   2,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
