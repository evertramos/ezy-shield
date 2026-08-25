package vhostdetect

// Tests for the issue #488 detection sources: Traefik docker labels, Traefik
// local config (YAML + TOML), and nginx server_name directives. Fixture
// domains are example.com/example.org per the repo's data-hygiene rules.

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// labelFakeCLI serves one container whose inspect output carries env AND
// label lines, exactly like the combined template production requests.
type labelFakeCLI struct {
	ps      string
	inspect string
}

func (f labelFakeCLI) Ps(context.Context, string) (string, error)              { return f.ps, nil }
func (f labelFakeCLI) Inspect(context.Context, string, string) (string, error) { return f.inspect, nil }

func TestDetect_TraefikDockerLabels(t *testing.T) {
	t.Parallel()
	cli := labelFakeCLI{
		ps: "web\ttraefik/whoami:latest\n",
		inspect: strings.Join([]string{
			"PATH=/usr/bin",
			"traefik.enable=true",
			"traefik.http.routers.web.rule=Host(`app.example.com`, `www.example.com`) || Host(`alt.example.org`)",
			"traefik.tcp.routers.db.rule=HostSNI(`sni.example.com`)",
			"traefik.http.routers.web.entrypoints=websecure",
		}, "\n"),
	}

	vhosts, err := Detect(context.Background(), cli)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(vhosts) != 1 || vhosts[0].Source != SourceTraefikDocker {
		t.Fatalf("expected one traefik-docker vhost, got %+v", vhosts)
	}
	want := []string{"app.example.com", "www.example.com", "alt.example.org", "sni.example.com"}
	if !reflect.DeepEqual(vhosts[0].Domains, want) {
		t.Fatalf("domains = %v, want %v", vhosts[0].Domains, want)
	}
}

func TestDetect_BothConventionsOnOneContainer(t *testing.T) {
	t.Parallel()
	cli := labelFakeCLI{
		ps: "app\tnginx:latest\n",
		inspect: strings.Join([]string{
			"VIRTUAL_HOST=env.example.com",
			"traefik.http.routers.app.rule=Host(`label.example.com`)",
		}, "\n"),
	}
	vhosts, err := Detect(context.Background(), cli)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(vhosts) != 2 {
		t.Fatalf("expected one vhost per convention, got %+v", vhosts)
	}
	if got := AllDomains(vhosts); !reflect.DeepEqual(got, []string{"env.example.com", "label.example.com"}) {
		t.Fatalf("AllDomains = %v", got)
	}
}

func TestParseTraefikRule(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		rule string
		want []string
	}{
		{"single backtick", "Host(`a.example.com`)", []string{"a.example.com"}},
		{"multi host", "Host(`a.example.com`, `b.example.com`)", []string{"a.example.com", "b.example.com"}},
		{"or forms", "Host(`a.example.com`) || HostSNI(`b.example.org`)", []string{"a.example.com", "b.example.org"}},
		{"double quotes", `Host("q.example.com")`, []string{"q.example.com"}},
		{"combined with path", "Host(`a.example.com`) && PathPrefix(`/api`)", []string{"a.example.com"}},
		{"wildcard normalized", "HostRegexp(`x`) || Host(`*.example.com`)", []string{"example.com"}},
		{"no host", "PathPrefix(`/x`)", nil},
		{"unclosed paren", "Host(`a.example.com`", nil},
		{"garbage tokens dropped", "Host(`not a hostname`, `ok.example.com`)", []string{"ok.example.com"}},
		{"injection-ish content dropped", "Host(`$(rm -rf /)`, `evil;.example.com`)", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := parseTraefikRule(tc.rule); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseTraefikRule(%q) = %v, want %v", tc.rule, got, tc.want)
			}
		})
	}
}

func TestDetectLocal_TraefikFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFixture(t, dir, "dynamic.yml", `
http:
  routers:
    web:
      rule: "Host(`+"`yml.example.com`"+`) || Host(`+"`yml2.example.com`"+`)"
      service: web
`)
	writeFixture(t, dir, "extra.toml", `
[http.routers.api]
  rule = "Host(`+"`toml.example.com`"+`)"
  service = "api"
`)
	writeFixture(t, dir, "notes.txt", "rule: Host(`ignored.example.com`)") // wrong extension

	vhosts := DetectLocal(LocalPaths{TraefikDirs: []string{dir}})
	if len(vhosts) != 1 || vhosts[0].Source != SourceTraefikFile {
		t.Fatalf("expected one traefik-file vhost, got %+v", vhosts)
	}
	want := []string{"yml.example.com", "yml2.example.com", "toml.example.com"}
	if !reflect.DeepEqual(vhosts[0].Domains, want) {
		t.Fatalf("domains = %v, want %v", vhosts[0].Domains, want)
	}
}

func TestDetectLocal_NginxServerNames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFixture(t, dir, "site-a", `
server {
    listen 80;
    server_name a.example.com www.a.example.com;
}
`)
	writeFixture(t, dir, "site-b.conf", `
server {
    server_name _;
}
server {
    server_name *.b.example.org .c.example.org $host localhost;
    # server_name commented.example.com;
}
`)

	vhosts := DetectLocal(LocalPaths{NginxDirs: []string{dir}})
	if len(vhosts) != 1 || vhosts[0].Source != SourceNginxFile {
		t.Fatalf("expected one nginx-file vhost, got %+v", vhosts)
	}
	want := []string{"a.example.com", "www.a.example.com", "b.example.org", "c.example.org"}
	if !reflect.DeepEqual(vhosts[0].Domains, want) {
		t.Fatalf("domains = %v, want %v", vhosts[0].Domains, want)
	}
}

func TestDetectLocal_MissingDirsAreSilent(t *testing.T) {
	t.Parallel()
	vhosts := DetectLocal(LocalPaths{
		TraefikDirs: []string{filepath.Join(t.TempDir(), "nope")},
		NginxDirs:   []string{filepath.Join(t.TempDir(), "also-nope")},
	})
	if len(vhosts) != 0 {
		t.Fatalf("missing dirs must be silently skipped, got %+v", vhosts)
	}
}

func TestDetectLocal_OversizedFileSkipped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	big := "server_name huge.example.com;\n" + strings.Repeat("#pad\n", (maxLocalFileBytes/5)+1)
	writeFixture(t, dir, "huge.conf", big)
	writeFixture(t, dir, "ok.conf", "server_name ok.example.com;\n")

	vhosts := DetectLocal(LocalPaths{NginxDirs: []string{dir}})
	if len(vhosts) != 1 || !reflect.DeepEqual(vhosts[0].Domains, []string{"ok.example.com"}) {
		t.Fatalf("oversized file must be skipped, small file kept: %+v", vhosts)
	}
}

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"a.example.com":     "a.example.com",
		"*.example.com":     "example.com",
		".example.com":      "example.com",
		"example.com.":      "example.com",
		"_":                 "",
		"localhost":         "", // no dot — not a resolvable FQDN for CDN checks
		"$host":             "",
		"evil;.example.com": "",
		"-bad.example.com":  "",
		"":                  "",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func writeFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
