// SPDX-License-Identifier: AGPL-3.0-only

package main

// Doctor checks for a tcp:// Docker Engine endpoint (issue #579).
//
// Pointing docker.host at tcp://127.0.0.1:2375 is only a privilege REDUCTION
// while something in front of the engine actually filters: a bare engine
// listening on a TCP port is the docker group, minus the group — anyone who
// reaches it can start a privileged container and own the host. That claim is
// cheap to verify and impossible to infer from configuration, so doctor asks
// the endpoint itself:
//
//	GET  /_ping                 is it there at all?
//	POST /containers/create     is it refusing the one call that matters?
//
// The create probe sends an empty JSON body, which cannot create anything
// even on a permissive engine (no image is named, so the engine rejects the
// request) — the point is the STATUS, not the outcome. A filtering proxy
// answers 403; an engine answers with a 4xx/5xx of its own, and that answer
// is the finding.
//
// Both probes are bounded by a request timeout, and neither ever prints a
// response body: this endpoint is a network peer whose bytes are untrusted
// (SECURITY-REVIEW.md §1).

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/evertramos/ezy-shield/internal/collector"
	"github.com/evertramos/ezy-shield/internal/config"
)

const (
	dockerEndpointReachName   = "docker: endpoint reachable"
	dockerEndpointReadOnly    = "docker: endpoint is read-only"
	dockerEndpointUnixHint    = "docker.host is a unix socket -- service-user socket access is evaluated by the socket check above"
	dockerCreateProbeBodyMax  = 4096
	dockerCreateProbeEndpoint = "/containers/create"
)

// checkDockerHostEndpoint runs the tcp-endpoint probes for the configured
// docker.host. Both checks are N/A when the endpoint is a unix socket (or
// nothing is configured, which means the default socket).
func checkDockerHostEndpoint(ctx context.Context, configDir string) []CheckResult {
	cfg, err := config.LoadConfig(filepath.Join(configDir, "config.yaml"))
	if err != nil {
		// The config.yaml checks already report an unloadable file; saying
		// it twice adds noise, not information.
		return []CheckResult{
			{Name: dockerEndpointReachName, Status: statusNA, Hint: "config.yaml not loadable"},
			{Name: dockerEndpointReadOnly, Status: statusNA, Hint: "config.yaml not loadable"},
		}
	}
	ep, err := collector.ParseDockerHost(cfg.DockerHost())
	if err != nil {
		// Validate() rejects this at load, so reaching here means a config
		// that never passed validation. Report it without echoing the value.
		return []CheckResult{
			{Name: dockerEndpointReachName, Status: statusFail,
				Hint: "docker.host is not a valid endpoint -- run '" + progName + " config validate'"},
			{Name: dockerEndpointReadOnly, Status: statusNA, Hint: "endpoint not usable"},
		}
	}
	if !ep.IsTCP() {
		return []CheckResult{
			{Name: dockerEndpointReachName, Status: statusNA, Hint: dockerEndpointUnixHint},
			{Name: dockerEndpointReadOnly, Status: statusNA, Hint: dockerEndpointUnixHint},
		}
	}

	client := collector.NewDockerAPIClient(ep)
	defer client.CloseIdleConnections()

	reach := dockerEndpointPing(ctx, client, ep)
	if reach.Status != statusPass {
		return []CheckResult{reach, {Name: dockerEndpointReadOnly, Status: statusNA,
			Hint: "endpoint not reachable -- read-only probe skipped"}}
	}
	return []CheckResult{reach, dockerEndpointCreateRefused(ctx, client, ep)}
}

// dockerEndpointPing reports whether GET /_ping answers 200. Anything else —
// a transport error, a redirect, an error status — is a FAIL, because a
// collector pointed at this endpoint would silently observe nothing.
func dockerEndpointPing(ctx context.Context, client *http.Client, ep collector.DockerEndpoint) CheckResult {
	status, err := dockerProbe(ctx, client, http.MethodGet, ep.URL("/_ping"), "")
	if err != nil {
		return CheckResult{Name: dockerEndpointReachName, Status: statusFail,
			Hint: fmt.Sprintf("%s did not answer: %v -- is the socket proxy running and published on that address?",
				ep.String(), err)}
	}
	if status != http.StatusOK {
		return CheckResult{Name: dockerEndpointReachName, Status: statusFail,
			Hint: fmt.Sprintf("%s answered HTTP %d to GET /_ping -- expected 200; "+
				"a filtering proxy must allow PING as well as CONTAINERS (and EVENTS for the exec watcher)",
				ep.String(), status)}
	}
	return CheckResult{Name: dockerEndpointReachName, Status: statusPass, Hint: ep.String()}
}

// dockerEndpointCreateRefused reports whether the endpoint refuses container
// creation. A refusal (401/403/405) is the whole point of putting a proxy
// there; any other answer means the endpoint forwards writes to the engine,
// which is root-equivalent access over the network.
func dockerEndpointCreateRefused(ctx context.Context, client *http.Client, ep collector.DockerEndpoint) CheckResult {
	// "{}" names no image, so no container can result from this request on
	// any engine — only its status code is informative.
	status, err := dockerProbe(ctx, client, http.MethodPost, ep.URL(dockerCreateProbeEndpoint), "{}")
	if err != nil {
		return CheckResult{Name: dockerEndpointReadOnly, Status: statusFail,
			Hint: fmt.Sprintf("could not verify that %s refuses container creation: %v -- "+
				"treat the endpoint as untrusted until this check passes", ep.String(), err)}
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusMethodNotAllowed:
		return CheckResult{Name: dockerEndpointReadOnly, Status: statusPass,
			Hint: fmt.Sprintf("%s refuses POST %s (HTTP %d) -- endpoint is read-only",
				ep.String(), dockerCreateProbeEndpoint, status)}
	default:
		return CheckResult{Name: dockerEndpointReadOnly, Status: statusFail,
			Hint: fmt.Sprintf("%s accepted POST %s (HTTP %d instead of 403) -- this endpoint accepts container "+
				"creation, i.e. root-equivalent access to this host over the network. Put a filtering proxy in "+
				"front of the engine (CONTAINERS and EVENTS only) or point docker.host back at the unix socket",
				ep.String(), dockerCreateProbeEndpoint, status)}
	}
}

// dockerProbe performs one bounded request and returns its status code. The
// body is drained to a hard cap and discarded: it is attacker-adjacent input
// and must never reach a hint, a log line or an error string.
func dockerProbe(ctx context.Context, client *http.Client, method, url, body string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, collector.DockerRequestTimeout)
	defer cancel()

	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		// url.Error quotes the request URL, which is the operator's own
		// endpoint (never a secret and never log-derived), so this is safe
		// to surface; the response body still never is.
		return 0, err
	}
	defer resp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, dockerCreateProbeBodyMax))
	return resp.StatusCode, nil
}
