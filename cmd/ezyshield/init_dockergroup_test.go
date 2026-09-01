// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// Tests for issue #574: `init` must never add the ezyshield service user to
// the root-equivalent 'docker' group on its own. The grant needs BOTH a
// docker log source configured in this run AND an explicit opt-in.

func TestDockerLogSources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state *wizardState
		want  int
	}{
		{"nil state", nil, 0},
		{"no collectors", &wizardState{}, 0},
		{
			name: "file collectors only",
			state: &wizardState{webCollectors: []webServerCollector{
				{Kind: "file", Path: "/var/log/nginx/access.log", Parser: "nginx"},
			}},
			want: 0,
		},
		{
			name: "one docker collector",
			state: &wizardState{webCollectors: []webServerCollector{
				{Kind: "docker", Container: "proxy", Parser: "nginx"},
			}},
			want: 1,
		},
		{
			name: "mixed collectors count only docker",
			state: &wizardState{webCollectors: []webServerCollector{
				{Kind: "file", Path: "/var/log/nginx/access.log", Parser: "nginx"},
				{Kind: "docker", Container: "proxy", Parser: "nginx"},
				{Kind: "docker", Container: "caddy", Parser: "caddy"},
			}},
			want: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := dockerLogSources(tc.state); got != tc.want {
				t.Errorf("dockerLogSources = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestShouldGrantDockerGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		dockerSources int
		optIn         bool
		want          bool
	}{
		{"no docker source, no opt-in", 0, false, false},
		// --docker-group on a host with no docker collector grants nothing:
		// the flag is consent, not a reason.
		{"no docker source, opt-in", 0, true, false},
		// The --yes / default path: collectors are configured, consent was
		// never given, so nothing is granted.
		{"docker source, no opt-in", 2, false, false},
		{"docker source and opt-in", 1, true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldGrantDockerGroup(tc.dockerSources, tc.optIn); got != tc.want {
				t.Errorf("shouldGrantDockerGroup(%d, %v) = %v, want %v",
					tc.dockerSources, tc.optIn, got, tc.want)
			}
		})
	}
}

// TestApplyDockerGroupDecision_WarnsWhenDeclined covers the two branches that
// touch no system state: a run with no docker source says nothing, and a
// declined run warns loudly (in the live output AND the final summary) that
// the collectors it just wrote cannot read anything.
func TestApplyDockerGroupDecision_WarnsWhenDeclined(t *testing.T) {
	t.Parallel()

	t.Run("no docker source is silent", func(t *testing.T) {
		t.Parallel()
		var buf strings.Builder
		p := &wPrinter{w: &buf}
		sum := &initSummary{}
		state := &wizardState{webCollectors: []webServerCollector{
			{Kind: "file", Path: "/var/log/nginx/access.log", Parser: "nginx"},
		}}

		applyDockerGroupDecision(p, styler{}, state, sum)

		if buf.String() != "" {
			t.Errorf("output = %q, want nothing when no docker collector is configured", buf.String())
		}
		if len(sum.configured) != 0 || len(sum.skipped) != 0 {
			t.Errorf("summary touched: configured=%v skipped=%v", sum.configured, sum.skipped)
		}
	})

	t.Run("declined opt-in warns and records the consequence", func(t *testing.T) {
		t.Parallel()
		var buf strings.Builder
		p := &wPrinter{w: &buf}
		sum := &initSummary{}
		state := &wizardState{
			webCollectors:    []webServerCollector{{Kind: "docker", Container: "proxy", Parser: "nginx"}},
			dockerGroupOptIn: false,
		}

		applyDockerGroupDecision(p, styler{}, state, sum)

		if !strings.Contains(buf.String(), "not granted") {
			t.Errorf("output %q does not warn that the group was not granted", buf.String())
		}
		if len(sum.configured) != 0 {
			t.Errorf("configured = %v, want nothing granted", sum.configured)
		}
		if len(sum.skipped) != 1 || sum.skipped[0] != dockerGroupSkippedLine {
			t.Fatalf("skipped = %v, want the docker-group warning line", sum.skipped)
		}
		for _, want := range []string{"docker group", "not granted", "container logs"} {
			if !strings.Contains(dockerGroupSkippedLine, want) {
				t.Errorf("skipped line %q missing %q", dockerGroupSkippedLine, want)
			}
		}
	})
}

// TestDockerGroupPromptNamesTheConsequence guards the wording: an operator who
// reads only this line must learn that "yes" is root on the host.
func TestDockerGroupPromptNamesTheConsequence(t *testing.T) {
	t.Parallel()
	for _, want := range []string{"docker", "root-equivalent", "privileged container"} {
		if !strings.Contains(dockerGroupPrompt, want) {
			t.Errorf("prompt %q missing %q", dockerGroupPrompt, want)
		}
	}
}

// TestAskQuestions_DockerGroupOptIn drives the real prompt sequence: a
// detected docker web server produces a docker collector, and the group is
// granted only when the operator answers y.
func TestAskQuestions_DockerGroupOptIn(t *testing.T) {
	tests := []struct {
		name  string
		input string // collector confirm, then the docker-group answer
		want  bool
	}{
		{"declined by default (empty answer)", "y\n\n", false},
		{"declined explicitly", "y\nn\n", false},
		{"accepted explicitly", "y\ny\n", true},
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

			if n := dockerLogSources(state); n != 1 {
				t.Fatalf("dockerLogSources = %d, want 1 (collectors: %+v)", n, state.webCollectors)
			}
			if state.dockerGroupOptIn != tc.want {
				t.Errorf("dockerGroupOptIn = %v, want %v", state.dockerGroupOptIn, tc.want)
			}
			if got := shouldGrantDockerGroup(dockerLogSources(state), state.dockerGroupOptIn); got != tc.want {
				t.Errorf("shouldGrantDockerGroup = %v, want %v", got, tc.want)
			}
			if !strings.Contains(out, "root-equivalent") {
				t.Errorf("the docker group prompt did not name the consequence; output: %q", out)
			}
		})
	}
}

// TestAskQuestions_YesModeNeverGrantsDockerGroup is the core regression test:
// --yes accepts safe defaults, and this default is No — even on a host where
// docker collectors are accepted by the same --yes run.
func TestAskQuestions_YesModeNeverGrantsDockerGroup(t *testing.T) {
	state := &wizardState{webServers: []detectedWebServer{{
		Kind:      "nginx",
		Location:  "docker",
		Parser:    "nginx",
		Container: "proxy",
		Image:     "nginx:latest",
	}}}

	_ = captureStdout(t, func() {
		askQuestions(os.Stdout, nil, state, true, styler{}, t.TempDir())
	})

	if n := dockerLogSources(state); n != 1 {
		t.Fatalf("dockerLogSources = %d, want 1 (--yes accepts the detected collector)", n)
	}
	if state.dockerGroupOptIn {
		t.Error("--yes opted the service user into the docker group; it must never do that")
	}
	if shouldGrantDockerGroup(dockerLogSources(state), state.dockerGroupOptIn) {
		t.Error("--yes alone must not grant the docker group")
	}
}

// TestDockerGroupFlagAndAnswersKey checks the non-interactive surface: the
// --docker-group flag defaults to false, overrides the answers file only when
// set, and applyAnswers carries the key into the wizard state.
func TestDockerGroupFlagAndAnswersKey(t *testing.T) {
	t.Parallel()

	t.Run("flag defaults to false and is not implied by --yes", func(t *testing.T) {
		t.Parallel()
		cmd := newInitCmd()
		f := cmd.Flags().Lookup("docker-group")
		if f == nil {
			t.Fatal("init has no --docker-group flag")
		}
		if f.DefValue != "false" {
			t.Errorf("--docker-group default = %q, want false", f.DefValue)
		}
		if !strings.Contains(f.Usage, "root-equivalent") {
			t.Errorf("--docker-group help %q does not name the consequence", f.Usage)
		}
		if err := cmd.Flags().Parse([]string{"--yes"}); err != nil {
			t.Fatalf("parsing --yes: %v", err)
		}
		if cmd.Flags().Changed("docker-group") {
			t.Error("--yes marked --docker-group as set")
		}
	})

	t.Run("unset flag does not clobber the answers file", func(t *testing.T) {
		t.Parallel()
		cmd := newInitCmd()
		if err := cmd.Flags().Parse(nil); err != nil {
			t.Fatalf("parsing: %v", err)
		}
		a := &initAnswers{}
		a.Collectors.DockerGroup = true
		applyFlagOverrides(cmd, a)
		if !a.Collectors.DockerGroup {
			t.Error("unset --docker-group cleared collectors.docker_group from the answers file")
		}
	})

	t.Run("flag overrides the answers file", func(t *testing.T) {
		t.Parallel()
		cmd := newInitCmd()
		if err := cmd.Flags().Parse([]string{"--docker-group=true"}); err != nil {
			t.Fatalf("parsing --docker-group: %v", err)
		}
		a := &initAnswers{}
		applyFlagOverrides(cmd, a)
		if !a.Collectors.DockerGroup {
			t.Error("--docker-group did not reach the answers")
		}

		state := &wizardState{}
		applyAnswers(state, a)
		if !state.dockerGroupOptIn {
			t.Error("applyAnswers did not carry docker_group into the wizard state")
		}
	})

	t.Run("answers file without the key never opts in", func(t *testing.T) {
		t.Parallel()
		a := &initAnswers{}
		a.Collectors.Web = []answersWebCollector{{Kind: "docker", Container: "proxy", Parser: "nginx"}}
		state := &wizardState{}
		applyAnswers(state, a)
		if state.dockerGroupOptIn {
			t.Error("a docker collector in the answers file implied the group grant")
		}
		if shouldGrantDockerGroup(dockerLogSources(state), state.dockerGroupOptIn) {
			t.Error("scripted docker collectors must not grant the group on their own")
		}
	})
}
