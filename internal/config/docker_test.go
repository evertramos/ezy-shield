// SPDX-License-Identifier: AGPL-3.0-only

package config

// Validation of the docker: section (issue #579). The endpoint decides how
// much of the host the log-parsing daemon can reach, so every rejection here
// is a privilege boundary, not a typo check.

import (
	"strings"
	"testing"
)

func TestValidateDockerHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cfg         *DockerCfg
		wantErr     bool
		errContains string
	}{
		{name: "absent section keeps the default socket", cfg: nil},
		{name: "empty host keeps the default socket", cfg: &DockerCfg{}},
		{name: "default unix socket", cfg: &DockerCfg{Host: "unix:///var/run/docker.sock"}},
		{name: "custom unix socket", cfg: &DockerCfg{Host: "unix:///run/docker/docker.sock"}},
		{name: "tcp loopback v4", cfg: &DockerCfg{Host: "tcp://127.0.0.1:2375"}},
		{name: "tcp loopback v6", cfg: &DockerCfg{Host: "tcp://[::1]:2375"}},

		{name: "tcp non-loopback needs allow_remote",
			cfg: &DockerCfg{Host: "tcp://192.0.2.10:2375"}, wantErr: true, errContains: "loopback"},
		{name: "tcp non-loopback with allow_remote",
			cfg: &DockerCfg{Host: "tcp://192.0.2.10:2375", AllowRemote: true}},
		{name: "tcp v6 non-loopback needs allow_remote",
			cfg: &DockerCfg{Host: "tcp://[2001:db8::1]:2375"}, wantErr: true, errContains: "loopback"},
		{name: "a name is never proven loopback",
			cfg: &DockerCfg{Host: "tcp://localhost:2375"}, wantErr: true, errContains: "loopback"},

		{name: "http scheme rejected",
			cfg: &DockerCfg{Host: "http://127.0.0.1:2375"}, wantErr: true, errContains: "unix:// or tcp://"},
		{name: "ssh scheme rejected",
			cfg: &DockerCfg{Host: "ssh://docker@192.0.2.10"}, wantErr: true, errContains: "unix:// or tcp://"},
		{name: "missing scheme rejected",
			cfg: &DockerCfg{Host: "/var/run/docker.sock"}, wantErr: true, errContains: "missing scheme"},
		{name: "relative unix path rejected",
			cfg: &DockerCfg{Host: "unix://var/run/docker.sock"}, wantErr: true, errContains: "absolute path"},
		{name: "tcp without port rejected",
			cfg: &DockerCfg{Host: "tcp://127.0.0.1"}, wantErr: true, errContains: "host:port"},
		{name: "tcp without host rejected",
			cfg: &DockerCfg{Host: "tcp://:2375"}, wantErr: true, errContains: "requires a host"},

		{name: "allow_remote without a host is meaningless",
			cfg: &DockerCfg{AllowRemote: true}, wantErr: true, errContains: "only applies to a tcp://"},
		{name: "allow_remote with a unix socket is meaningless",
			cfg:     &DockerCfg{Host: "unix:///var/run/docker.sock", AllowRemote: true},
			wantErr: true, errContains: "only applies to a tcp://"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Config{
				DataDir:    "/var/lib/ezyshield",
				SocketPath: "/run/ezyshield/ezyshield.sock",
				Docker:     tc.cfg,
			}
			err := c.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate() = nil, want an error for %+v", tc.cfg)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q does not mention %q", err, tc.errContains)
				}
				if !strings.HasPrefix(err.Error(), "docker:") {
					t.Errorf("error %q is not attributed to the docker section", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(): %v", err)
			}
		})
	}
}

// TestConfigDockerHostDefault: an install with no docker: section must resolve
// to the historical unix socket, so nothing changes for it.
func TestConfigDockerHostDefault(t *testing.T) {
	t.Parallel()

	const defaultHost = "unix:///var/run/docker.sock"
	var nilCfg *Config
	if got := nilCfg.DockerHost(); got != defaultHost {
		t.Errorf("nil config: DockerHost() = %q, want %q", got, defaultHost)
	}
	if got := (&Config{}).DockerHost(); got != defaultHost {
		t.Errorf("absent section: DockerHost() = %q, want %q", got, defaultHost)
	}
	if got := (&Config{Docker: &DockerCfg{}}).DockerHost(); got != defaultHost {
		t.Errorf("empty host: DockerHost() = %q, want %q", got, defaultHost)
	}
	if got := (&Config{Docker: &DockerCfg{Host: "tcp://127.0.0.1:2375"}}).DockerHost(); got != "tcp://127.0.0.1:2375" {
		t.Errorf("configured host: DockerHost() = %q, want %q", got, "tcp://127.0.0.1:2375")
	}
}

// TestLoadDockerSection checks the YAML keys are the documented ones and that
// an unknown key inside the section is refused like everywhere else.
func TestLoadDockerSection(t *testing.T) {
	t.Parallel()

	const good = `
data_dir: /var/lib/ezyshield
socket_path: /run/ezyshield/ezyshield.sock
docker:
  host: tcp://127.0.0.1:2375
collectors:
  - kind: docker
    container: web
    parser: nginx
`
	cfg, err := LoadConfigReader(strings.NewReader(good), "config.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.DockerHost() != "tcp://127.0.0.1:2375" {
		t.Errorf("DockerHost() = %q", cfg.DockerHost())
	}

	const unknownKey = `
data_dir: /var/lib/ezyshield
socket_path: /run/ezyshield/ezyshield.sock
docker:
  socket: /var/run/docker.sock
`
	if _, err := LoadConfigReader(strings.NewReader(unknownKey), "config.yaml"); err == nil {
		t.Error("an unknown key inside docker: was accepted")
	}
}
