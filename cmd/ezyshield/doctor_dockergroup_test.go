// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for issue #574's doctor check: the membership survives package
// upgrades, so doctor is what surfaces it on already-provisioned hosts.

// writeGroupFile writes a /etc/group-formatted fixture and returns its path.
func writeGroupFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing group file: %v", err)
	}
	return path
}

func TestGroupFileMembership(t *testing.T) {
	t.Parallel()

	const groups = `root:x:0:
# a comment line
adm:x:4:syslog,admin

docker:x:989:admin,ezyshield
systemd-journal:x:101:ezyshield
plugdev:x:46:
`

	tests := []struct {
		name         string
		group, user  string
		wantExists   bool
		wantIsMember bool
	}{
		{"member of docker", "docker", "ezyshield", true, true},
		{"other member of docker", "docker", "admin", true, true},
		{"group exists, user is not a member", "docker", "nobody", true, false},
		{"group with an empty member list", "plugdev", "ezyshield", true, false},
		{"group absent", "lxd", "ezyshield", false, false},
		{"prefix must not match", "dock", "ezyshield", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := writeGroupFile(t, groups)
			exists, member, err := groupFileMembership(path, tc.group, tc.user)
			if err != nil {
				t.Fatalf("groupFileMembership: %v", err)
			}
			if exists != tc.wantExists || member != tc.wantIsMember {
				t.Errorf("exists=%v member=%v, want exists=%v member=%v",
					exists, member, tc.wantExists, tc.wantIsMember)
			}
		})
	}

	t.Run("missing file returns an error", func(t *testing.T) {
		t.Parallel()
		if _, _, err := groupFileMembership(filepath.Join(t.TempDir(), "absent"), "docker", "ezyshield"); err == nil {
			t.Error("want an error for a missing group file")
		}
	})
}

func TestServiceUserDockerGroupCheck(t *testing.T) {
	t.Parallel()

	const withMembership = "docker:x:989:admin,ezyshield\n"
	const withoutMembership = "docker:x:989:admin\n"
	const noDockerGroup = "adm:x:4:admin\n"

	dockerCollectorCfg := "data_dir: /tmp/x\ncollectors:\n  - kind: docker\n    container: proxy\n    parser: nginx\n"
	dockerExecCfg := "data_dir: /tmp/x\ncollectors:\n  - kind: journald\n    unit: sshd\ndocker_exec:\n  enabled: true\n"
	fileCollectorCfg := "data_dir: /tmp/x\ncollectors:\n  - kind: file\n    path: /var/log/nginx/access.log\n    parser: nginx\n"

	tests := []struct {
		name       string
		groupFile  string
		config     string // empty = no config.yaml written
		wantStatus string
		wantHint   []string
		denyHint   []string
	}{
		{
			name:       "no docker group on the host",
			groupFile:  noDockerGroup,
			config:     fileCollectorCfg,
			wantStatus: statusNA,
			wantHint:   []string{"no 'docker' group"},
		},
		{
			name:       "service user is not a member",
			groupFile:  withoutMembership,
			config:     dockerCollectorCfg,
			wantStatus: statusPass,
			wantHint:   []string{"not in the 'docker' group"},
		},
		{
			name:       "member with docker collectors is an accepted risk",
			groupFile:  withMembership,
			config:     dockerCollectorCfg,
			wantStatus: statusWarn,
			wantHint:   []string{"root-equivalent", "required by the configured docker collectors", "accepted risk"},
			denyHint:   []string{"gpasswd"},
		},
		{
			name:       "member with docker_exec is an accepted risk",
			groupFile:  withMembership,
			config:     dockerExecCfg,
			wantStatus: statusWarn,
			wantHint:   []string{"root-equivalent", "required by the configured docker collectors"},
			denyHint:   []string{"gpasswd"},
		},
		{
			name:       "member with no docker source must be revoked",
			groupFile:  withMembership,
			config:     fileCollectorCfg,
			wantStatus: statusWarn,
			wantHint: []string{
				"root-equivalent",
				"no docker collector is configured",
				"gpasswd -d ezyshield docker",
				"systemctl restart ezyshield",
			},
		},
		{
			name:       "member with an unreadable config still gets the revoke hint",
			groupFile:  withMembership,
			wantStatus: statusWarn,
			wantHint:   []string{"root-equivalent", "no docker collector is configured", "gpasswd -d ezyshield docker"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			groupPath := filepath.Join(dir, "group")
			if err := os.WriteFile(groupPath, []byte(tc.groupFile), 0o600); err != nil {
				t.Fatalf("writing group file: %v", err)
			}
			configPath := filepath.Join(dir, "config.yaml")
			if tc.config != "" {
				if err := os.WriteFile(configPath, []byte(tc.config), 0o600); err != nil {
					t.Fatalf("writing config: %v", err)
				}
			}

			res := serviceUserDockerGroupCheck(groupPath, configPath)
			if res.Status != tc.wantStatus {
				t.Fatalf("status = %s, want %s (hint: %s)", res.Status, tc.wantStatus, res.Hint)
			}
			for _, want := range tc.wantHint {
				if !strings.Contains(res.Hint, want) {
					t.Errorf("hint %q missing %q", res.Hint, want)
				}
			}
			for _, deny := range tc.denyHint {
				if strings.Contains(res.Hint, deny) {
					t.Errorf("hint %q must not suggest %q when the collectors need the access", res.Hint, deny)
				}
			}
		})
	}

	t.Run("unreadable group file is N/A, never a false PASS", func(t *testing.T) {
		t.Parallel()
		res := serviceUserDockerGroupCheck(filepath.Join(t.TempDir(), "absent"), "")
		if res.Status != statusNA {
			t.Errorf("status = %s, want N/A", res.Status)
		}
	})
}

func TestConfigNeedsDockerSocket(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config string
		want   bool
	}{
		{"docker collector", "data_dir: /tmp/x\ncollectors:\n  - kind: docker\n    container: proxy\n    parser: nginx\n", true},
		{"docker exec watcher", "data_dir: /tmp/x\ncollectors: []\ndocker_exec:\n  enabled: true\n", true},
		{"docker exec disabled", "data_dir: /tmp/x\ncollectors: []\ndocker_exec:\n  enabled: false\n", false},
		{"file collector only", "data_dir: /tmp/x\ncollectors:\n  - kind: file\n    path: /var/log/nginx/access.log\n    parser: nginx\n", false},
		{"no collectors", "data_dir: /tmp/x\ncollectors: []\n", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := configNeedsDockerSocket(writeTestConfig(t, tc.config)); got != tc.want {
				t.Errorf("configNeedsDockerSocket = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("missing config is false", func(t *testing.T) {
		t.Parallel()
		if configNeedsDockerSocket(filepath.Join(t.TempDir(), "absent.yaml")) {
			t.Error("a missing config must not claim to need the docker socket")
		}
	})
}

// TestCheckDockerSocketHint_NamesTheConsequence guards the remediation hint:
// it must never read as a casual "just run usermod -aG docker".
func TestCheckDockerSocketHint_NamesTheConsequence(t *testing.T) {
	t.Parallel()
	res := checkDockerSocket()
	if res.Status != statusFail {
		t.Skipf("docker socket check returned %s on this host — hint not exercised", res.Status)
	}
	if strings.Contains(res.Hint, "usermod -aG docker") {
		t.Errorf("hint hands out a bare usermod command: %q", res.Hint)
	}
	if !strings.Contains(res.Hint, "root-equivalent") {
		t.Errorf("hint %q does not name the consequence of joining the docker group", res.Hint)
	}
}
