// SPDX-License-Identifier: AGPL-3.0-only

package main

// How init lets the daemon read container logs (issue #579).
//
// There are three ways, and they are NOT equivalent — they differ by how much
// of the host the log-parsing daemon can reach if it is ever compromised. The
// wizard presents them in privilege order and makes the operator pick:
//
//	1. file  — the container already writes its access log to a host path
//	           (a compose volume). EzyShield reads a file. It gets no Docker
//	           access at all: the smallest grant that works.
//	2. proxy — a filtering, read-only proxy in front of the Engine socket,
//	           published on 127.0.0.1. EzyShield speaks the Engine API over
//	           tcp but the proxy answers only container logs and events, and
//	           refuses container creation, exec and mounts.
//	3. group — membership in the host's 'docker' group. That group IS the
//	           Engine API: a compromised daemon can start a privileged
//	           container, i.e. become root on the host. Last resort (#574).
//
// init never starts a proxy — that is a change to the operator's own stack.
// It writes docker.host, prints the compose snippet to run, and defers
// verification to `doctor`, which proves the endpoint really does refuse
// container creation.

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/evertramos/ezy-shield/internal/collector"
)

// dockerAccessPath is one of the three ways above.
type dockerAccessPath string

const (
	dockerAccessFile  dockerAccessPath = "file"
	dockerAccessProxy dockerAccessPath = "proxy"
	dockerAccessGroup dockerAccessPath = "group"
)

// defaultDockerProxyHost is the endpoint init proposes and writes for the
// proxy path: loopback only, so the Engine API is never exposed off-host.
const defaultDockerProxyHost = "tcp://127.0.0.1:2375"

// dockerAccessFlagConflict is returned when a run asks for both the scoped
// endpoint and the root-equivalent group. They are alternatives, and silently
// preferring one would hand out a privilege the operator did not intend.
const dockerAccessFlagConflict = "--docker-host and --docker-group are mutually exclusive: " +
	"the read-only socket proxy replaces the 'docker' group, it does not accompany it " +
	"(collectors.docker_host / collectors.docker_group in the answers file)"

// defaultDockerAccess picks the pre-selected option. When a host-path access
// log already exists, reading that file is both the least privilege and the
// least work, so it leads. Otherwise the proxy leads: the group is never a
// default anywhere.
func defaultDockerAccess(hostLogPath string) dockerAccessPath {
	if hostLogPath != "" {
		return dockerAccessFile
	}
	return dockerAccessProxy
}

// parseDockerAccessChoice maps a typed answer ("1", "2", "3", or the option
// name) to a path, falling back to def on anything unrecognised — an operator
// who fat-fingers the prompt gets the safe pre-selection, never an upgrade.
func parseDockerAccessChoice(answer string, def dockerAccessPath) dockerAccessPath {
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "1", "file":
		return dockerAccessFile
	case "2", "proxy":
		return dockerAccessProxy
	case "3", "group":
		return dockerAccessGroup
	default:
		return def
	}
}

// resolveDockerAccessAnswers turns the scripted inputs (--docker-host /
// collectors.docker_host and --docker-group / collectors.docker_group) into a
// path. Neither set means no Docker grant at all: the collectors are written
// and the run warns they cannot read anything yet, exactly as before #579.
func resolveDockerAccessAnswers(dockerHost string, dockerGroup bool) (dockerAccessPath, string, error) {
	host := strings.TrimSpace(dockerHost)
	if host != "" && dockerGroup {
		return "", "", errors.New(dockerAccessFlagConflict)
	}
	if host != "" {
		if err := validateDockerProxyHost(host); err != nil {
			return "", "", err
		}
		return dockerAccessProxy, host, nil
	}
	if dockerGroup {
		return dockerAccessGroup, "", nil
	}
	return "", "", nil
}

// validateDockerProxyHost applies the same rules as config validation, so a
// scripted run fails at the flag rather than writing a config.yaml the daemon
// will refuse to load. A non-loopback tcp endpoint is rejected outright here:
// docker.allow_remote is a deliberate hand edit, not something init offers.
func validateDockerProxyHost(host string) error {
	ep, err := collector.ParseDockerHost(host)
	if err != nil {
		return fmt.Errorf("--docker-host: %w", err)
	}
	if ep.IsTCP() && !ep.IsLoopback() {
		return fmt.Errorf("--docker-host: %s is not a loopback address -- publish the socket proxy on "+
			"127.0.0.1 so the Engine API is never reachable off-host (set docker.allow_remote in config.yaml "+
			"by hand if you really mean it)", ep.String())
	}
	return nil
}

// dockerHostLogPath returns a host-side access-log path this run already reads
// with a file collector for the same parser, or "" when there is none.
//
// It deliberately does NOT stat the conventional paths (/var/log/nginx/... and
// friends): that file existing says nothing about whether THIS container's log
// lands there — a host that merely has the package installed would make the
// wizard propose a log belonging to something else. The only signal used is a
// file collector the run itself configured, which detection produces only for a
// web server actually running on the host with a log present. Anything weaker
// is left to the operator, who types the path at the prompt.
func dockerHostLogPath(state *wizardState) string {
	if state == nil {
		return ""
	}
	for _, wc := range state.webCollectors {
		if wc.Kind != "docker" {
			continue
		}
		for _, other := range state.webCollectors {
			if other.Kind == "file" && other.Parser == wc.Parser && other.Path != "" {
				return other.Path
			}
		}
	}
	return ""
}

// dockerAccessMenu renders the three options with the pre-selection marked.
// The wording states the consequence of each grant, not its mechanism: an
// operator who reads only this menu must still learn that option 3 makes the
// daemon root-equivalent.
func dockerAccessMenu(hostLogPath string, def dockerAccessPath) string {
	mark := func(p dockerAccessPath) string {
		if p == def {
			return " (recommended)"
		}
		return ""
	}
	fileHint := "the container writes its access log to a host path (a compose volume)"
	if hostLogPath != "" {
		fileHint = "found a host-side log at " + hostLogPath
	}
	var b strings.Builder
	b.WriteString("  How should EzyShield read the container logs?\n")
	fmt.Fprintf(&b, "    1) host log file%s — no Docker access at all; %s\n", mark(dockerAccessFile), fileHint)
	fmt.Fprintf(&b, "    2) read-only socket proxy%s — EzyShield talks to a filtering proxy on %s\n",
		mark(dockerAccessProxy), defaultDockerProxyHost)
	fmt.Fprintf(&b, "       that serves container logs and events and refuses container creation\n")
	fmt.Fprintf(&b, "    3) 'docker' group%s — ROOT-EQUIVALENT on this host: any process running as\n", mark(dockerAccessGroup))
	fmt.Fprintf(&b, "       ezyshield could start a privileged container\n")
	return b.String()
}

// dockerSocketProxyCompose is the ready-to-paste stack for option 2. Every
// capability except the two EzyShield actually uses is left off, and the port
// is published on loopback only.
func dockerSocketProxyCompose(host string) string {
	// SplitHostPort, not a string split: an IPv6 endpoint is
	// "[::1]:2375" and cutting on the first colon would take the address
	// apart instead of the port.
	port := "2375"
	if ep, err := collector.ParseDockerHost(host); err == nil && ep.IsTCP() {
		if _, p, splitErr := net.SplitHostPort(ep.Address); splitErr == nil {
			port = p
		}
	}
	return `services:
  ezyshield-docker-proxy:
    image: tecnativa/docker-socket-proxy
    restart: unless-stopped
    environment:
      CONTAINERS: 1        # GET /containers/<name>/logs
      EVENTS: 1            # GET /events (docker exec watcher)
      POST: 0              # refuses container create/exec/start
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "127.0.0.1:` + port + `:2375"`
}

// askDockerAccess runs the three-way choice and applies it to state. It is
// called only when this run actually configured docker log collectors.
//
// Option 1 rewrites those collectors to kind: file, so the generated
// config.yaml stops mentioning Docker entirely — that is what makes it the
// smallest grant. A collector whose host path the operator cannot supply is
// left as-is and picked up by the usual "cannot read anything yet" warning.
func askDockerAccess(p *wPrinter, st styler,
	ask func(question, def string) string,
	askBool func(question string, def bool) bool,
	state *wizardState, yes bool,
) {
	// --yes accepts safe defaults, and none of these three is one: two are
	// privilege grants and the third rewrites a collector to read a file the
	// wizard cannot know exists. An unattended run that was not pre-answered
	// therefore configures no access at all and falls through to the honest
	// "collectors cannot read anything yet" warning — the same rule #574
	// applied to the group.
	if yes && state.dockerAccess == "" {
		return
	}

	hostLogPath := dockerHostLogPath(state)
	def := defaultDockerAccess(hostLogPath)
	// A pre-answered run (--docker-host / --docker-group) has already made
	// the choice; do not ask again.
	if state.dockerAccess != "" {
		def = state.dockerAccess
	}

	p.println("")
	p.printf("%s", dockerAccessMenu(hostLogPath, def))
	choice := parseDockerAccessChoice(ask("Choice", string(def)), def)
	state.dockerAccess = choice

	switch choice {
	case dockerAccessFile:
		p.println(st.ok("EzyShield will read a host file — the container needs a log volume, " +
			"e.g. './logs:/var/log/nginx' in its compose service; init does not edit your stack"))
		for i := range state.webCollectors {
			wc := &state.webCollectors[i]
			if wc.Kind != "docker" {
				continue
			}
			path := ask(fmt.Sprintf("Host path of the %s access log for container %s", wc.Parser, wc.Container),
				hostLogPath)
			if path == "" {
				continue
			}
			wc.Kind = "file"
			wc.Path = path
			wc.Container = ""
		}
		state.dockerGroupOptIn = false
		state.dockerHost = ""

	case dockerAccessProxy:
		defHost := defaultDockerProxyHost
		if state.dockerHost != "" {
			// Pre-answered by --docker-host: that value is the default, so a
			// --yes run keeps it instead of silently reverting to 2375.
			defHost = state.dockerHost
		}
		host := ask("Docker endpoint for the proxy", defHost)
		if err := validateDockerProxyHost(host); err != nil {
			p.println(st.warn(fmt.Sprintf("%v — using %s", err, defaultDockerProxyHost)))
			host = defaultDockerProxyHost
		}
		state.dockerHost = host
		state.dockerGroupOptIn = false
		p.println(st.ok("docker.host: " + host + " — run this proxy in your stack, then verify with '" +
			progName + " doctor':"))
		p.println(dockerSocketProxyCompose(host))

	case dockerAccessGroup:
		// Unchanged wording from #574: the confirmation still names the
		// consequence, and still defaults to No.
		state.dockerGroupOptIn = askBool(dockerGroupPrompt, state.dockerGroupOptIn)
		state.dockerHost = ""
	}
}
