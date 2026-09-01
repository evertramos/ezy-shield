// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the tcp docker.host probes (issue #579). The interesting case is
// the one that FAILS: an endpoint that happily accepts POST /containers/create
// is root-equivalent access to the host over the network, and doctor must say
// so instead of reporting a healthy connection.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeDockerHostConfig writes a minimal config.yaml with the given docker
// host and returns its directory.
func writeDockerHostConfig(t *testing.T, host string) string {
	t.Helper()
	dir := t.TempDir()
	body := "data_dir: /var/lib/ezyshield\nsocket_path: /run/ezyshield/ezyshield.sock\n"
	if host != "" {
		body += "docker:\n  host: " + host + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return dir
}

func findCheck(t *testing.T, checks []CheckResult, name string) CheckResult {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not present in %+v", name, checks)
	return CheckResult{}
}

// TestCheckDockerHostEndpoint_UnixIsNA: nothing to probe when the endpoint is
// the local socket — that grant is evaluated by the socket check.
func TestCheckDockerHostEndpoint_UnixIsNA(t *testing.T) {
	t.Parallel()

	for _, host := range []string{"", "unix:///var/run/docker.sock"} {
		dir := writeDockerHostConfig(t, host)
		checks := checkDockerHostEndpoint(context.Background(), dir)
		if len(checks) != 2 {
			t.Fatalf("want 2 checks, got %+v", checks)
		}
		for _, c := range checks {
			if c.Status != statusNA {
				t.Errorf("host %q: %s = %s, want N/A", host, c.Name, c.Status)
			}
			if !strings.Contains(c.Hint, "socket check") {
				t.Errorf("host %q: hint %q does not point at the socket check", host, c.Hint)
			}
		}
	}
}

// TestCheckDockerHostEndpoint_ReadOnlyProxy: the shape a filtering proxy has —
// /_ping answers, container creation is refused.
func TestCheckDockerHostEndpoint_ReadOnlyProxy(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("HOSTILE-BODY-MARKER"))
			return
		}
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(srv.Close)

	dir := writeDockerHostConfig(t, "tcp://"+srv.Listener.Addr().String())
	checks := checkDockerHostEndpoint(context.Background(), dir)

	if got := findCheck(t, checks, dockerEndpointReachName); got.Status != statusPass {
		t.Errorf("reachability = %s (%s), want PASS", got.Status, got.Hint)
	}
	ro := findCheck(t, checks, dockerEndpointReadOnly)
	if ro.Status != statusPass {
		t.Errorf("read-only = %s (%s), want PASS", ro.Status, ro.Hint)
	}
	if !strings.Contains(ro.Hint, "read-only") {
		t.Errorf("hint %q does not say the endpoint is read-only", ro.Hint)
	}
	for _, c := range checks {
		if strings.Contains(c.Hint, "HOSTILE-BODY-MARKER") {
			t.Errorf("response body leaked into a hint: %q", c.Hint)
		}
	}
}

// TestCheckDockerHostEndpoint_AcceptsCreateFails: a bare engine (or a proxy
// with POST enabled) answers the create request with its own error status.
// Any answer that is not a refusal means the endpoint forwards writes.
func TestCheckDockerHostEndpoint_AcceptsCreateFails(t *testing.T) {
	t.Parallel()

	// The statuses a real engine returns to POST /containers/create with an
	// empty body — none of them is a refusal to serve the endpoint.
	for _, status := range []int{
		http.StatusCreated, http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("HOSTILE-BODY-MARKER"))
				return
			}
			_, _ = w.Write([]byte("OK"))
		}))

		dir := writeDockerHostConfig(t, "tcp://"+srv.Listener.Addr().String())
		checks := checkDockerHostEndpoint(context.Background(), dir)
		srv.Close()

		if got := findCheck(t, checks, dockerEndpointReachName); got.Status != statusPass {
			t.Errorf("status %d: reachability = %s, want PASS", status, got.Status)
		}
		ro := findCheck(t, checks, dockerEndpointReadOnly)
		if ro.Status != statusFail {
			t.Fatalf("status %d: read-only = %s (%s), want FAIL", status, ro.Status, ro.Hint)
		}
		if !strings.Contains(ro.Hint, "root-equivalent") {
			t.Errorf("status %d: hint %q does not name the consequence", status, ro.Hint)
		}
		if strings.Contains(ro.Hint, "HOSTILE-BODY-MARKER") {
			t.Errorf("status %d: response body leaked into the hint: %q", status, ro.Hint)
		}
	}
}

// TestCheckDockerHostEndpoint_Unreachable: nothing listening means the
// collectors would observe nothing, which is a FAIL, and the read-only probe
// is not attempted.
func TestCheckDockerHostEndpoint_Unreachable(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.Listener.Addr().String()
	srv.Close() // free the port: connections are now refused

	dir := writeDockerHostConfig(t, "tcp://"+addr)
	checks := checkDockerHostEndpoint(context.Background(), dir)

	if got := findCheck(t, checks, dockerEndpointReachName); got.Status != statusFail {
		t.Errorf("reachability = %s (%s), want FAIL", got.Status, got.Hint)
	}
	if got := findCheck(t, checks, dockerEndpointReadOnly); got.Status != statusNA {
		t.Errorf("read-only = %s, want N/A when the endpoint is unreachable", got.Status)
	}
}

// TestCheckDockerHostEndpoint_ProbeTimesOut: an endpoint that accepts the
// connection and then never answers must not wedge doctor, and "could not
// verify" is a FAIL — an unverified endpoint is not a trusted one.
func TestCheckDockerHostEndpoint_ProbeTimesOut(t *testing.T) {
	t.Parallel()

	// stop releases the stuck handler at teardown: httptest.Server.Close
	// waits for outstanding requests, and a handler parked on the request
	// context alone can outlive the client that abandoned it.
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			select { // never answers
			case <-r.Context().Done():
			case <-stop:
			}
			return
		}
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(func() {
		close(stop)
		srv.Close()
	})

	dir := writeDockerHostConfig(t, "tcp://"+srv.Listener.Addr().String())

	// A short deadline stands in for the production request timeout so the
	// test does not have to wait it out.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	checks := checkDockerHostEndpoint(ctx, dir)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("probe took %s; it must be bounded", elapsed)
	}

	ro := findCheck(t, checks, dockerEndpointReadOnly)
	if ro.Status != statusFail {
		t.Errorf("read-only = %s (%s), want FAIL when the probe cannot complete", ro.Status, ro.Hint)
	}
	if !strings.Contains(ro.Hint, "could not verify") {
		t.Errorf("hint %q does not say the check was inconclusive", ro.Hint)
	}
}
