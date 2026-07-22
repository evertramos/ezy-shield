package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestBuildAllowlist verifies issue #210: the generated allowlist contains
// only loopback, the detected docker subnets (if any), and the operator's
// public IP -- never a blanket RFC1918 entry.
func TestBuildAllowlist(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		state   *wizardState
		want    []string
		wantNot []string // substrings that must NOT appear in any entry
	}{
		{
			name:  "no docker, no public IP -- loopback only",
			state: &wizardState{},
			want:  []string{"127.0.0.1/32", "::1/128"},
			wantNot: []string{
				"172.16.0.0/12", "172.17.0.0/16", "10.", "192.168.",
			},
		},
		{
			name:  "no docker, with public IP -- no RFC1918 entry at all",
			state: &wizardState{publicIP: "203.0.113.7"},
			want:  []string{"127.0.0.1/32", "::1/128", "203.0.113.7/32"},
			wantNot: []string{
				"172.16.0.0/12", "172.17.0.0/16",
			},
		},
		{
			name: "docker with real subnets -- only those subnets, never the /12",
			state: &wizardState{
				hasDocker:       true,
				dockerAllowlist: []string{"172.20.0.0/16", "172.21.0.0/24"},
				publicIP:        "203.0.113.7",
			},
			want: []string{
				"127.0.0.1/32", "::1/128",
				"172.20.0.0/16", "172.21.0.0/24",
				"203.0.113.7/32",
			},
			wantNot: []string{"172.16.0.0/12"},
		},
		{
			name: "docker enumeration failure -- fallback default bridge only",
			state: &wizardState{
				hasDocker:       true,
				dockerAllowlist: []string{defaultDockerBridgeSubnet},
			},
			want:    []string{"127.0.0.1/32", "::1/128", "172.17.0.0/16"},
			wantNot: []string{"172.16.0.0/12"},
		},
		{
			name: "docker detected but zero bridge subnets found -- no docker entry added",
			state: &wizardState{
				hasDocker:       true,
				dockerAllowlist: nil,
			},
			want:    []string{"127.0.0.1/32", "::1/128"},
			wantNot: []string{"172."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildAllowlist(tt.state)

			for _, w := range tt.want {
				found := false
				for _, g := range got {
					if g == w {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("buildAllowlist() = %v, missing expected entry %q", got, w)
				}
			}
			for _, entry := range got {
				for _, forbidden := range tt.wantNot {
					if strings.Contains(entry, forbidden) {
						t.Errorf("buildAllowlist() = %v, entry %q must not contain %q", got, entry, forbidden)
					}
				}
			}
			if len(got) != len(tt.want) {
				t.Errorf("buildAllowlist() returned %d entries %v, want exactly %v", len(got), got, tt.want)
			}
		})
	}
}

// TestDetectDockerBridgeSubnets exercises the fallback contract: any
// enumeration error must fall back to exactly defaultDockerBridgeSubnet,
// never the 172.16.0.0/12 supernet and never a silently empty allowlist.
func TestDetectDockerBridgeSubnets(t *testing.T) {
	origLister := dockerNetworkLister
	defer func() { dockerNetworkLister = origLister }()

	t.Run("enumeration succeeds with real subnets", func(t *testing.T) {
		dockerNetworkLister = func(context.Context) ([]string, error) {
			return []string{"172.18.0.0/16", "172.19.0.0/24"}, nil
		}
		subnets, usedFallback := detectDockerBridgeSubnets()
		if usedFallback {
			t.Error("usedFallback = true, want false on successful enumeration")
		}
		want := []string{"172.18.0.0/16", "172.19.0.0/24"}
		if len(subnets) != len(want) || subnets[0] != want[0] || subnets[1] != want[1] {
			t.Errorf("subnets = %v, want %v", subnets, want)
		}
	})

	t.Run("enumeration succeeds with zero networks", func(t *testing.T) {
		dockerNetworkLister = func(context.Context) ([]string, error) {
			return nil, nil
		}
		subnets, usedFallback := detectDockerBridgeSubnets()
		if usedFallback {
			t.Error("usedFallback = true, want false when enumeration succeeds with zero results")
		}
		if len(subnets) != 0 {
			t.Errorf("subnets = %v, want empty", subnets)
		}
	})

	t.Run("enumeration fails -- falls back to default bridge subnet only", func(t *testing.T) {
		dockerNetworkLister = func(context.Context) ([]string, error) {
			return nil, errors.New("docker daemon unreachable")
		}
		subnets, usedFallback := detectDockerBridgeSubnets()
		if !usedFallback {
			t.Error("usedFallback = false, want true on enumeration error")
		}
		if len(subnets) != 1 || subnets[0] != defaultDockerBridgeSubnet {
			t.Errorf("subnets = %v, want [%s]", subnets, defaultDockerBridgeSubnet)
		}
		for _, s := range subnets {
			if s == "172.16.0.0/12" {
				t.Error("fallback must never be the 172.16.0.0/12 supernet")
			}
		}
	})
}

// TestParseDockerBridgeSubnets exercises the untrusted-input handling
// (§1 SECURITY-REVIEW): docker's own JSON output is decoded strictly and
// every subnet is re-validated, never trusted verbatim.
func TestParseDockerBridgeSubnets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		want    []string
		wantErr bool
	}{
		{
			name:    "single bridge network",
			payload: `[{"Driver":"bridge","IPAM":{"Config":[{"Subnet":"172.17.0.0/16"}]}}]`,
			want:    []string{"172.17.0.0/16"},
		},
		{
			name: "multiple bridge networks, deduplicated",
			payload: `[
				{"Driver":"bridge","IPAM":{"Config":[{"Subnet":"172.17.0.0/16"}]}},
				{"Driver":"bridge","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]}},
				{"Driver":"bridge","IPAM":{"Config":[{"Subnet":"172.17.0.0/16"}]}}
			]`,
			want: []string{"172.17.0.0/16", "172.18.0.0/16"},
		},
		{
			name: "non-bridge drivers excluded (host, overlay, macvlan, none)",
			payload: `[
				{"Driver":"bridge","IPAM":{"Config":[{"Subnet":"172.17.0.0/16"}]}},
				{"Driver":"host","IPAM":{"Config":[]}},
				{"Driver":"overlay","IPAM":{"Config":[{"Subnet":"10.0.9.0/24"}]}},
				{"Driver":"macvlan","IPAM":{"Config":[{"Subnet":"192.168.100.0/24"}]}},
				{"Driver":"null","IPAM":{"Config":[]}}
			]`,
			want: []string{"172.17.0.0/16"},
		},
		{
			name: "unparsable subnet strings are skipped, never trusted verbatim",
			payload: `[{"Driver":"bridge","IPAM":{"Config":[
				{"Subnet":"not-a-cidr"},
				{"Subnet":"172.20.0.0/16"},
				{"Subnet":""}
			]}}]`,
			want: []string{"172.20.0.0/16"},
		},
		{
			name:    "malformed JSON returns an error, never a partial trust fallback",
			payload: `{not valid json`,
			wantErr: true,
		},
		{
			name:    "empty array -- no networks",
			payload: `[]`,
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseDockerBridgeSubnets([]byte(tt.payload))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestWriteGeneratedPolicy_AllowlistScoping is an end-to-end check that the
// generated policy.yaml carries the docker-derived allowlist (not the /12)
// and the commented opt-in example for broader ranges (issue #210 AC #1, #3).
func TestWriteGeneratedPolicy_AllowlistScoping(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/policy.yaml"

	state := &wizardState{
		hasDocker:       true,
		dockerAllowlist: []string{"172.22.0.0/16"},
	}
	if err := writeGeneratedPolicy(path, state); err != nil {
		t.Fatalf("writeGeneratedPolicy returned error: %v", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // t.TempDir()-controlled path
	if err != nil {
		t.Fatalf("reading policy.yaml: %v", err)
	}
	content := string(data)

	if strings.Contains(content, "172.16.0.0/12") {
		t.Error("generated policy.yaml must never contain the 172.16.0.0/12 supernet")
	}
	if !strings.Contains(content, "172.22.0.0/16") {
		t.Error("generated policy.yaml must contain the detected docker subnet")
	}
	if !strings.Contains(content, "allowlist always wins") {
		t.Error("generated policy.yaml must document the allowlist-wins trade-off in the opt-in example")
	}
}

// TestWriteGeneratedPolicy_NoDockerNoRFC1918Entry covers AC #2: non-docker
// hosts get no blanket RFC1918 entry at all.
func TestWriteGeneratedPolicy_NoDockerNoRFC1918Entry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/policy.yaml"

	state := &wizardState{hasDocker: false}
	if err := writeGeneratedPolicy(path, state); err != nil {
		t.Fatalf("writeGeneratedPolicy returned error: %v", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // t.TempDir()-controlled path
	if err != nil {
		t.Fatalf("reading policy.yaml: %v", err)
	}
	content := string(data)
	for _, forbidden := range []string{"172.16.0.0/12", "172.17.0.0/16"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("non-docker generated policy.yaml must not contain %q:\n%s", forbidden, content)
		}
	}
}
