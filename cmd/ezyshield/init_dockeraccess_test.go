// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the three container-log access paths init offers (issue #579).
// The invariant under test is that the root-equivalent path is never reached
// by accident: not by a default, not by a typo at the prompt, and not by
// combining flags.

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

func TestDefaultDockerAccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		hostLogPath string
		want        dockerAccessPath
	}{
		{name: "a host-side log exists — read the file, no Docker access at all",
			hostLogPath: "/var/log/nginx/access.log", want: dockerAccessFile},
		{name: "no host-side log — the read-only proxy leads",
			hostLogPath: "", want: dockerAccessProxy},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := defaultDockerAccess(tc.hostLogPath); got != tc.want {
				t.Errorf("defaultDockerAccess(%q) = %q, want %q", tc.hostLogPath, got, tc.want)
			}
		})
	}
	// The group is never a default, whatever the environment looks like.
	for _, p := range []string{"", "/var/log/nginx/access.log"} {
		if got := defaultDockerAccess(p); got == dockerAccessGroup {
			t.Errorf("defaultDockerAccess(%q) pre-selected the root-equivalent group", p)
		}
	}
}

func TestParseDockerAccessChoice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		answer string
		def    dockerAccessPath
		want   dockerAccessPath
	}{
		{answer: "1", def: dockerAccessProxy, want: dockerAccessFile},
		{answer: "2", def: dockerAccessFile, want: dockerAccessProxy},
		{answer: "3", def: dockerAccessFile, want: dockerAccessGroup},
		{answer: "file", def: dockerAccessProxy, want: dockerAccessFile},
		{answer: "proxy", def: dockerAccessFile, want: dockerAccessProxy},
		{answer: "GROUP", def: dockerAccessFile, want: dockerAccessGroup},
		{answer: " 2 ", def: dockerAccessFile, want: dockerAccessProxy},
		// Anything unrecognised keeps the safe pre-selection — a fat-fingered
		// answer must never be an upgrade.
		{answer: "", def: dockerAccessProxy, want: dockerAccessProxy},
		{answer: "y", def: dockerAccessProxy, want: dockerAccessProxy},
		{answer: "4", def: dockerAccessFile, want: dockerAccessFile},
		{answer: "sudo", def: dockerAccessFile, want: dockerAccessFile},
	}
	for _, tc := range tests {
		t.Run(tc.answer+"->"+string(tc.want), func(t *testing.T) {
			t.Parallel()
			if got := parseDockerAccessChoice(tc.answer, tc.def); got != tc.want {
				t.Errorf("parseDockerAccessChoice(%q, %q) = %q, want %q", tc.answer, tc.def, got, tc.want)
			}
		})
	}
}

func TestResolveDockerAccessAnswers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		host        string
		group       bool
		wantPath    dockerAccessPath
		wantHost    string
		wantErr     bool
		errContains string
	}{
		{name: "neither: no docker grant at all"},
		{name: "group only", group: true, wantPath: dockerAccessGroup},
		{name: "host only", host: "tcp://127.0.0.1:2375",
			wantPath: dockerAccessProxy, wantHost: "tcp://127.0.0.1:2375"},
		{name: "host is trimmed", host: "  tcp://127.0.0.1:2375  ",
			wantPath: dockerAccessProxy, wantHost: "tcp://127.0.0.1:2375"},
		{name: "custom unix socket", host: "unix:///run/docker/docker.sock",
			wantPath: dockerAccessProxy, wantHost: "unix:///run/docker/docker.sock"},
		{name: "both set is refused", host: "tcp://127.0.0.1:2375", group: true,
			wantErr: true, errContains: "mutually exclusive"},
		{name: "invalid scheme is refused", host: "http://127.0.0.1:2375",
			wantErr: true, errContains: "unix:// or tcp://"},
		{name: "non-loopback endpoint is refused", host: "tcp://192.0.2.10:2375",
			wantErr: true, errContains: "loopback"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path, host, err := resolveDockerAccessAnswers(tc.host, tc.group)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got path=%q host=%q", path, host)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q does not mention %q", err, tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if path != tc.wantPath {
				t.Errorf("path = %q, want %q", path, tc.wantPath)
			}
			if host != tc.wantHost {
				t.Errorf("host = %q, want %q", host, tc.wantHost)
			}
		})
	}
}

// TestDockerSocketProxyCompose guards the snippet init prints: it must grant
// exactly the two capabilities EzyShield uses, refuse writes, and publish on
// loopback only.
func TestDockerSocketProxyCompose(t *testing.T) {
	t.Parallel()

	snippet := dockerSocketProxyCompose(defaultDockerProxyHost)
	for _, want := range []string{
		"tecnativa/docker-socket-proxy",
		"CONTAINERS: 1",
		"EVENTS: 1",
		"POST: 0",
		"docker.sock:ro",
		`"127.0.0.1:2375:2375"`,
	} {
		if !strings.Contains(snippet, want) {
			t.Errorf("compose snippet missing %q:\n%s", want, snippet)
		}
	}
	// A custom port must reach the published mapping, still on loopback.
	if got := dockerSocketProxyCompose("tcp://127.0.0.1:2999"); !strings.Contains(got, `"127.0.0.1:2999:2375"`) {
		t.Errorf("custom port not honoured:\n%s", got)
	}
	if strings.Contains(snippet, "0.0.0.0") {
		t.Errorf("compose snippet publishes off-loopback:\n%s", snippet)
	}
}

// TestAskDockerAccess_Paths drives the real prompt sequence for each option
// and checks what each one writes into the wizard state.
func TestAskDockerAccess_Paths(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantHost      string
		wantGroup     bool
		wantCollector webServerCollector
		wantOutput    []string
	}{
		{
			name:          "option 1 converts the collector to a host file and grants nothing",
			input:         "y\n1\n/srv/site/logs/access.log\n",
			wantCollector: webServerCollector{Kind: "file", Path: "/srv/site/logs/access.log", Parser: "nginx"},
			wantOutput:    []string{"host file", "compose"},
		},
		{
			name:          "option 2 writes docker.host and prints the proxy stack",
			input:         "y\n2\n\n",
			wantHost:      defaultDockerProxyHost,
			wantCollector: webServerCollector{Kind: "docker", Container: "proxy", Parser: "nginx"},
			wantOutput:    []string{"tecnativa/docker-socket-proxy", "doctor"},
		},
		{
			name:          "option 2 with a custom loopback port",
			input:         "y\n2\ntcp://127.0.0.1:2999\n",
			wantHost:      "tcp://127.0.0.1:2999",
			wantCollector: webServerCollector{Kind: "docker", Container: "proxy", Parser: "nginx"},
		},
		{
			name:          "option 2 refuses a non-loopback endpoint and keeps the default",
			input:         "y\n2\ntcp://192.0.2.10:2375\n",
			wantHost:      defaultDockerProxyHost,
			wantCollector: webServerCollector{Kind: "docker", Container: "proxy", Parser: "nginx"},
			wantOutput:    []string{"loopback"},
		},
		{
			name:          "option 3 asks the root-equivalent confirmation",
			input:         "y\n3\ny\n",
			wantGroup:     true,
			wantCollector: webServerCollector{Kind: "docker", Container: "proxy", Parser: "nginx"},
			wantOutput:    []string{"root-equivalent"},
		},
		{
			name:          "option 3 declined grants nothing",
			input:         "y\n3\nn\n",
			wantCollector: webServerCollector{Kind: "docker", Container: "proxy", Parser: "nginx"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &wizardState{webServers: []detectedWebServer{{
				Kind:      "nginx",
				Location:  "docker",
				Parser:    "nginx",
				Container: "proxy",
				Image:     "nginx:latest",
			}}}
			sc := bufio.NewScanner(strings.NewReader(tc.input))
			out := captureStdout(t, func() {
				askQuestions(os.Stdout, sc, state, false, styler{}, t.TempDir())
			})

			if state.dockerHost != tc.wantHost {
				t.Errorf("dockerHost = %q, want %q", state.dockerHost, tc.wantHost)
			}
			if state.dockerGroupOptIn != tc.wantGroup {
				t.Errorf("dockerGroupOptIn = %v, want %v", state.dockerGroupOptIn, tc.wantGroup)
			}
			if len(state.webCollectors) != 1 || state.webCollectors[0] != tc.wantCollector {
				t.Errorf("webCollectors = %+v, want [%+v]", state.webCollectors, tc.wantCollector)
			}
			for _, want := range tc.wantOutput {
				if !strings.Contains(out, want) {
					t.Errorf("output does not mention %q:\n%s", want, out)
				}
			}
		})
	}
}

// TestRenderGeneratedConfig_DockerHost: docker.host reaches config.yaml only
// when the proxy path was chosen, so an unchanged install keeps an unchanged
// config.
func TestRenderGeneratedConfig_DockerHost(t *testing.T) {
	t.Parallel()

	withProxy := &wizardState{
		webCollectors: []webServerCollector{{Kind: "docker", Container: "proxy", Parser: "nginx"}},
		dockerHost:    "tcp://127.0.0.1:2375",
	}
	got, err := renderGeneratedConfig(withProxy)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(string(got), "docker:\n  host: tcp://127.0.0.1:2375\n") {
		t.Errorf("docker.host not written:\n%s", got)
	}

	withoutProxy := &wizardState{
		webCollectors: []webServerCollector{{Kind: "docker", Container: "proxy", Parser: "nginx"}},
	}
	got, err = renderGeneratedConfig(withoutProxy)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(string(got), "docker:") {
		t.Errorf("a run that chose no endpoint must not write a docker section:\n%s", got)
	}
}

// TestDockerHostLogPath_IgnoresTheHostFilesystem: the pre-selection must not
// depend on what happens to be installed on the machine running init. Only a
// file collector this run configured counts as evidence that a host-side log
// exists for that web server.
func TestDockerHostLogPath_IgnoresTheHostFilesystem(t *testing.T) {
	t.Parallel()

	onlyDocker := &wizardState{webCollectors: []webServerCollector{
		{Kind: "docker", Container: "proxy", Parser: "nginx"},
	}}
	if got := dockerHostLogPath(onlyDocker); got != "" {
		t.Errorf("dockerHostLogPath = %q, want empty (nothing in this run reads a host log)", got)
	}
	if got := defaultDockerAccess(dockerHostLogPath(onlyDocker)); got != dockerAccessProxy {
		t.Errorf("pre-selection = %q, want %q", got, dockerAccessProxy)
	}

	withFile := &wizardState{webCollectors: []webServerCollector{
		{Kind: "file", Path: "/srv/site/logs/access.log", Parser: "nginx"},
		{Kind: "docker", Container: "proxy", Parser: "nginx"},
	}}
	if got := dockerHostLogPath(withFile); got != "/srv/site/logs/access.log" {
		t.Errorf("dockerHostLogPath = %q, want the configured file collector's path", got)
	}

	otherParser := &wizardState{webCollectors: []webServerCollector{
		{Kind: "file", Path: "/var/log/apache2/access.log", Parser: "apache"},
		{Kind: "docker", Container: "proxy", Parser: "nginx"},
	}}
	if got := dockerHostLogPath(otherParser); got != "" {
		t.Errorf("dockerHostLogPath = %q, want empty (a different web server's log is not this one's)", got)
	}

	if got := dockerHostLogPath(nil); got != "" {
		t.Errorf("nil state: dockerHostLogPath = %q, want empty", got)
	}
}

// TestAskDockerAccess_YesModeConfiguresNothing: an unattended run that was not
// pre-answered must grant no access and must not rewrite a docker collector
// into a file collector pointing at a path the wizard cannot verify.
func TestAskDockerAccess_YesModeConfiguresNothing(t *testing.T) {
	state := &wizardState{webServers: []detectedWebServer{{
		Kind:      "nginx",
		Location:  "docker",
		Parser:    "nginx",
		Container: "proxy",
		Image:     "nginx:latest",
	}}}
	captureStdout(t, func() {
		askQuestions(os.Stdout, nil, state, true, styler{}, t.TempDir())
	})

	if n := dockerLogSources(state); n != 1 {
		t.Fatalf("dockerLogSources = %d, want 1 (--yes accepts the detected collector as a docker one)", n)
	}
	if state.dockerHost != "" {
		t.Errorf("dockerHost = %q, want empty (--yes must not point at a proxy nobody asked for)", state.dockerHost)
	}
	if state.dockerGroupOptIn {
		t.Error("--yes granted the docker group")
	}
	if state.dockerAccess != "" {
		t.Errorf("dockerAccess = %q, want empty (no path chosen)", state.dockerAccess)
	}
}

// TestNonInteractive_DockerHostPrecedence: the answers file supplies the
// endpoint, and --docker-host overrides it — the same layering every other
// scripted answer follows.
func TestNonInteractive_DockerHostPrecedence(t *testing.T) {
	t.Parallel()

	a := &initAnswers{Collectors: answersCollectors{DockerHost: "tcp://127.0.0.1:2375"}}

	state := &wizardState{}
	applyAnswers(state, a)
	if state.dockerHost != "tcp://127.0.0.1:2375" {
		t.Errorf("dockerHost = %q, want the answers-file endpoint", state.dockerHost)
	}
	if state.dockerGroupOptIn {
		t.Error("the endpoint must not imply the docker group")
	}

	cmd := newInitCmd()
	if err := cmd.Flags().Set("docker-host", "tcp://127.0.0.1:2999"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	applyFlagOverrides(cmd, a)
	if a.Collectors.DockerHost != "tcp://127.0.0.1:2999" {
		t.Errorf("answers.docker_host = %q, want the flag value", a.Collectors.DockerHost)
	}

	// An unset flag must never clobber the file value.
	fresh := &initAnswers{Collectors: answersCollectors{DockerHost: "tcp://127.0.0.1:2375"}}
	applyFlagOverrides(newInitCmd(), fresh)
	if fresh.Collectors.DockerHost != "tcp://127.0.0.1:2375" {
		t.Errorf("docker_host = %q, want the file value preserved", fresh.Collectors.DockerHost)
	}
}

// TestApplyDockerGroupDecision_ProxyReplacesTheGroup: with an endpoint
// configured there is no missing grant, so the run must not warn about one.
func TestApplyDockerGroupDecision_ProxyReplacesTheGroup(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	p := &wPrinter{w: &buf}
	sum := &initSummary{}
	state := &wizardState{
		webCollectors: []webServerCollector{{Kind: "docker", Container: "proxy", Parser: "nginx"}},
		dockerHost:    "tcp://127.0.0.1:2375",
	}

	applyDockerGroupDecision(p, styler{}, state, sum)

	if len(sum.skipped) != 0 {
		t.Errorf("skipped = %v, want no missing-grant warning when an endpoint is configured", sum.skipped)
	}
	if len(sum.configured) != 1 || !strings.Contains(sum.configured[0], "tcp://127.0.0.1:2375") {
		t.Fatalf("configured = %v, want the endpoint line", sum.configured)
	}
	if !strings.Contains(buf.String(), "doctor") {
		t.Errorf("output %q does not defer verification to doctor", buf.String())
	}
}
