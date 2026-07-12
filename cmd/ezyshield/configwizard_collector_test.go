package main

// Tests for `config collector <name>` (issue #103): the post-install
// collector wizard built on the shared init sub-flow
// (confirmWebServerCollectors). Collectors carry no secrets, so the focus
// is merge semantics (add / replace / remove), abort safety (nothing
// written), and the atomic write + .bak contract shared with the other
// component wizards.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// nginxFileEntry is appended to validConfig when a test needs a pre-existing
// web collector (validConfig itself only carries the journald sshd entry).
const nginxFileEntry = `  - kind: file
    path: /var/log/nginx/access.log
    parser: nginx
`

// TestRunConfigComponent_CollectorWebHappyPath adds one collector per web
// server name on a fresh installation, for both sources the schema supports.
func TestRunConfigComponent_CollectorWebHappyPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		answers []string // scripted `ask` answers, in prompt order
		want    config.CollectorCfg
	}{
		{"nginx", []string{"file", "/srv/logs/nginx-access.log"},
			config.CollectorCfg{Kind: "file", Path: "/srv/logs/nginx-access.log", Parser: "nginx"}},
		{"apache", []string{"file", "/srv/logs/apache-access.log"},
			config.CollectorCfg{Kind: "file", Path: "/srv/logs/apache-access.log", Parser: "apache"}},
		{"traefik", []string{"file", "/srv/logs/traefik-access.log"},
			config.CollectorCfg{Kind: "file", Path: "/srv/logs/traefik-access.log", Parser: "traefik"}},
		{"caddy", []string{"file", "/srv/logs/caddy-access.log"},
			config.CollectorCfg{Kind: "file", Path: "/srv/logs/caddy-access.log", Parser: "caddy"}},
		{"nginx", []string{"docker", "web-nginx"},
			config.CollectorCfg{Kind: "docker", Container: "web-nginx", Parser: "nginx"}},
	}
	for _, tc := range cases {
		t.Run(tc.name+"_"+tc.want.Kind, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			cfgPath := writeFile(t, dir, "config.yaml", validConfig)
			prompt := &scriptedPrompter{strings: tc.answers} // confirm bool → default yes

			out := captureStep(t, func(p *wPrinter) {
				if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
					"collector", tc.name, cfgPath); code != validateExitOK {
					t.Errorf("exit code = %d, want 0", code)
				}
			})

			cfg, err := config.LoadConfig(cfgPath)
			if err != nil {
				t.Fatalf("saved config does not load: %v", err)
			}
			if len(cfg.Collectors) != 2 {
				t.Fatalf("collectors = %+v, want journald + new entry", cfg.Collectors)
			}
			if cfg.Collectors[0].Kind != "journald" || cfg.Collectors[0].Unit != "sshd" {
				t.Errorf("pre-existing journald entry lost: %+v", cfg.Collectors[0])
			}
			if cfg.Collectors[1] != tc.want {
				t.Errorf("new entry = %+v, want %+v", cfg.Collectors[1], tc.want)
			}
			if bak, err := os.ReadFile(cfgPath + ".bak"); err != nil || string(bak) != validConfig { //nolint:gosec // test path
				t.Errorf(".bak missing or differs from original (err=%v)", err)
			}
			for _, want := range []string{"Changed keys:", "added entry", "config validate"} {
				if !strings.Contains(out, want) {
					t.Errorf("stdout missing %q:\n%s", want, out)
				}
			}
		})
	}
}

// TestRunConfigComponent_CollectorWebReplacesExisting reconfigures an
// existing nginx collector: the wizard must replace the matching entry
// (same parser), never append a duplicate — including a file→docker switch.
func TestRunConfigComponent_CollectorWebReplacesExisting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		answers []string
		want    config.CollectorCfg
	}{
		{"new path", []string{"file", "/srv/www/access.log"},
			config.CollectorCfg{Kind: "file", Path: "/srv/www/access.log", Parser: "nginx"}},
		{"file to docker", []string{"docker", "proxy"},
			config.CollectorCfg{Kind: "docker", Container: "proxy", Parser: "nginx"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			cfgPath := writeFile(t, dir, "config.yaml", validConfig+nginxFileEntry)
			prompt := &scriptedPrompter{strings: tc.answers}

			out := captureStep(t, func(p *wPrinter) {
				if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
					"collector", "nginx", cfgPath); code != validateExitOK {
					t.Errorf("exit code = %d, want 0", code)
				}
			})

			cfg, err := config.LoadConfig(cfgPath)
			if err != nil {
				t.Fatalf("saved config does not load: %v", err)
			}
			if len(cfg.Collectors) != 2 {
				t.Fatalf("collectors = %+v, want exactly journald + nginx", cfg.Collectors)
			}
			if cfg.Collectors[1] != tc.want {
				t.Errorf("nginx entry = %+v, want %+v", cfg.Collectors[1], tc.want)
			}
			if !strings.Contains(out, "replaced entry") {
				t.Errorf("summary should say 'replaced entry':\n%s", out)
			}
		})
	}
}

// TestRunConfigComponent_CollectorSSH covers the journald wizard: replacing
// the existing SSH entry (unit override included) and adding a fresh one.
func TestRunConfigComponent_CollectorSSH(t *testing.T) {
	t.Parallel()

	t.Run("replaces existing unit", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig) // journald unit: sshd
		prompt := &scriptedPrompter{strings: []string{"ssh"}}    // override unit

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"collector", "sshd", cfgPath); code != validateExitOK {
				t.Errorf("exit code = %d, want 0", code)
			}
		})

		cfg, err := config.LoadConfig(cfgPath)
		if err != nil {
			t.Fatalf("saved config does not load: %v", err)
		}
		want := config.CollectorCfg{Kind: "journald", Unit: "ssh"}
		if len(cfg.Collectors) != 1 || cfg.Collectors[0] != want {
			t.Errorf("collectors = %+v, want single %+v", cfg.Collectors, want)
		}
		if !strings.Contains(out, "replaced entry (kind=journald, unit=ssh)") {
			t.Errorf("summary should show the replaced journald entry:\n%s", out)
		}
	})

	t.Run("adds when absent", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml",
			"data_dir: /var/lib/ezyshield\ncollectors: []\n")
		prompt := &scriptedPrompter{strings: []string{"sshd"}}

		captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"collector", "sshd", cfgPath); code != validateExitOK {
				t.Errorf("exit code = %d, want 0", code)
			}
		})

		cfg, err := config.LoadConfig(cfgPath)
		if err != nil {
			t.Fatalf("saved config does not load: %v", err)
		}
		want := config.CollectorCfg{Kind: "journald", Unit: "sshd"}
		if len(cfg.Collectors) != 1 || cfg.Collectors[0] != want {
			t.Errorf("collectors = %+v, want single %+v", cfg.Collectors, want)
		}
	})
}

// TestRunConfigComponent_CollectorRemove is the disable path: declining the
// configure prompt offers removal of the matching entry. Accepting drops it;
// declining (or having nothing to remove) must leave the file untouched.
func TestRunConfigComponent_CollectorRemove(t *testing.T) {
	t.Parallel()

	t.Run("web entry removed", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig+nginxFileEntry)
		prompt := &scriptedPrompter{bools: []bool{false, true}} // decline configure, accept remove

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"collector", "nginx", cfgPath); code != validateExitOK {
				t.Errorf("exit code = %d, want 0", code)
			}
		})

		cfg, err := config.LoadConfig(cfgPath)
		if err != nil {
			t.Fatalf("saved config does not load: %v", err)
		}
		if len(cfg.Collectors) != 1 || cfg.Collectors[0].Kind != "journald" {
			t.Errorf("collectors = %+v, want only the journald entry left", cfg.Collectors)
		}
		if !strings.Contains(out, "removed entry (kind=file, path=/var/log/nginx/access.log, parser=nginx)") {
			t.Errorf("summary should show the removed entry:\n%s", out)
		}
	})

	t.Run("ssh entry removed", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig)
		prompt := &scriptedPrompter{bools: []bool{false, true}}

		captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"collector", "sshd", cfgPath); code != validateExitOK {
				t.Errorf("exit code = %d, want 0", code)
			}
		})

		cfg, err := config.LoadConfig(cfgPath)
		if err != nil {
			t.Fatalf("saved config does not load: %v", err)
		}
		if len(cfg.Collectors) != 0 {
			t.Errorf("collectors = %+v, want none", cfg.Collectors)
		}
	})

	t.Run("removal declined leaves file untouched", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig+nginxFileEntry)
		prompt := &scriptedPrompter{bools: []bool{false, false}}

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"collector", "nginx", cfgPath); code != validateExitError {
				t.Errorf("exit code = %d, want %d", code, validateExitError)
			}
		})
		assertUnchanged(t, cfgPath, validConfig+nginxFileEntry)
		if !strings.Contains(out, "No changes were made.") {
			t.Errorf("stdout should state that nothing changed:\n%s", out)
		}
	})

	t.Run("nothing to remove", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		cfgPath := writeFile(t, dir, "config.yaml", validConfig) // no nginx entry
		prompt := &scriptedPrompter{bools: []bool{false}}

		out := captureStep(t, func(p *wPrinter) {
			if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
				"collector", "nginx", cfgPath); code != validateExitError {
				t.Errorf("exit code = %d, want %d", code, validateExitError)
			}
		})
		assertUnchanged(t, cfgPath, validConfig)
		if !strings.Contains(out, "no nginx collector is configured") {
			t.Errorf("stdout should explain there is nothing to remove:\n%s", out)
		}
	})
}

// TestRunConfigComponent_CollectorAborts covers the two operator-input abort
// paths: an empty docker container name and an unsupported source keyword.
// Both must exit non-zero without touching config.yaml.
func TestRunConfigComponent_CollectorAborts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		answers []string
		wantOut string
	}{
		{"empty container name", []string{"docker"}, "no container name given"},
		{"invalid source", []string{"journald"}, `invalid log source "journald"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			cfgPath := writeFile(t, dir, "config.yaml", validConfig)
			prompt := &scriptedPrompter{strings: tc.answers}

			out := captureStep(t, func(p *wPrinter) {
				if code := runConfigComponent(context.Background(), p, prompt, cdnDeps{},
					"collector", "nginx", cfgPath); code != validateExitError {
					t.Errorf("exit code = %d, want %d", code, validateExitError)
				}
			})
			assertUnchanged(t, cfgPath, validConfig)
			if !strings.Contains(out, tc.wantOut) {
				t.Errorf("stdout missing %q:\n%s", tc.wantOut, out)
			}
		})
	}
}

// TestRunConfigComponent_CollectorUnknownName: a typo lists what IS registered.
func TestRunConfigComponent_CollectorUnknownName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml", validConfig)

	out := captureStep(t, func(p *wPrinter) {
		if code := runConfigComponent(context.Background(), p, &scriptedPrompter{}, cdnDeps{},
			"collector", "iis", cfgPath); code != validateExitError {
			t.Errorf("exit code = %d, want %d", code, validateExitError)
		}
	})
	for _, want := range []string{`unknown collector "iis"`, "apache", "caddy", "nginx", "sshd", "traefik"} {
		if !strings.Contains(out, want) {
			t.Errorf("error should name the miss and list collectors, missing %q:\n%s", want, out)
		}
	}
}

// assertUnchanged fails when config.yaml no longer matches want or a .bak
// appeared — aborted wizards must leave zero footprint on disk.
func assertUnchanged(t *testing.T, cfgPath, want string) {
	t.Helper()
	raw, err := os.ReadFile(cfgPath) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != want {
		t.Errorf("config.yaml was modified on an abort path:\n%s", raw)
	}
	if _, err := os.Stat(cfgPath + ".bak"); !os.IsNotExist(err) {
		t.Errorf(".bak must not exist on an abort path (err=%v)", err)
	}
}
