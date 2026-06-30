package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentifyDockerWebServer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, image string
		want        string
	}{
		{"my-nginx", "nginx:1.27", "nginx"},
		{"web", "library/nginx:alpine", "nginx"},
		{"traefik-proxy", "traefik:v2", "traefik"},
		{"caddy-server", "caddy:2", "caddy"},
		{"httpd-old", "library/httpd:2.4", "apache"},
		{"apache-front", "ubuntu/apache2:latest", "apache"},
		{"postgres", "postgres:16", ""},
		{"redis", "redis:7-alpine", ""},
	}
	for _, tc := range cases {
		c := dockerContainer{name: tc.name, image: tc.image}
		got := identifyDockerWebServer(c)
		if got != tc.want {
			t.Errorf("identifyDockerWebServer(%q,%q) = %q; want %q",
				tc.name, tc.image, got, tc.want)
		}
	}
}

func TestDetectDockerWebServers_MultipleKinds(t *testing.T) {
	t.Parallel()
	in := []dockerContainer{
		{name: "nginx-edge", image: "nginx:alpine", ports: ":80->80/tcp"},
		{name: "api", image: "company/api:1.0", ports: ":3000->3000/tcp"},
		{name: "traefik-1", image: "traefik:v2.10", ports: ":443->443/tcp"},
		{name: "redis", image: "redis:7"},
		{name: "caddy-static", image: "caddy:2-alpine"},
	}
	got := detectDockerWebServers(in)
	if len(got) != 3 {
		t.Fatalf("expected 3 web servers, got %d: %+v", len(got), got)
	}
	kinds := map[string]string{}
	for _, ws := range got {
		kinds[ws.Kind] = ws.Container
		if ws.Location != "docker" {
			t.Errorf("location: want docker, got %q", ws.Location)
		}
	}
	if kinds["nginx"] != "nginx-edge" {
		t.Errorf("nginx container = %q; want nginx-edge", kinds["nginx"])
	}
	if kinds["traefik"] != "traefik-1" {
		t.Errorf("traefik container = %q; want traefik-1", kinds["traefik"])
	}
	if kinds["caddy"] != "caddy-static" {
		t.Errorf("caddy container = %q; want caddy-static", kinds["caddy"])
	}
}

func TestDetectDockerWebServers_NilSafe(t *testing.T) {
	t.Parallel()
	got := detectDockerWebServers(nil)
	if got != nil {
		t.Errorf("expected nil for nil input, got %+v", got)
	}
}

// TestDetectDockerWebServers_ParserMapping makes sure each detected container
// is tagged with the parser config.LoadConfigReader accepts.
func TestDetectDockerWebServers_ParserMapping(t *testing.T) {
	t.Parallel()
	expected := map[string]string{
		"nginx":   "nginx",
		"apache":  "apache",
		"traefik": "traefik",
		"caddy":   "caddy",
	}
	in := []dockerContainer{
		{name: "nginx", image: "nginx"},
		{name: "apache", image: "httpd"},
		{name: "traefik", image: "traefik"},
		{name: "caddy", image: "caddy"},
	}
	got := detectDockerWebServers(in)
	if len(got) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(got))
	}
	for _, ws := range got {
		if expected[ws.Kind] != ws.Parser {
			t.Errorf("kind %q parser = %q; want %q", ws.Kind, ws.Parser, expected[ws.Kind])
		}
	}
}

func TestResolveLocalLogPath_PicksExisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	existing := filepath.Join(dir, "access.log")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	spec := webServerSpec{
		kind:     "test",
		logPaths: []string{filepath.Join(dir, "missing.log"), existing},
	}
	got, exists := resolveLocalLogPath(spec)
	if got != existing {
		t.Errorf("got %q; want %q", got, existing)
	}
	if !exists {
		t.Error("exists = false; want true")
	}
}

func TestResolveLocalLogPath_FallsBackToFirst(t *testing.T) {
	t.Parallel()
	spec := webServerSpec{
		kind:     "test",
		logPaths: []string{"/var/log/missing/a.log", "/var/log/missing/b.log"},
	}
	got, exists := resolveLocalLogPath(spec)
	if got != "/var/log/missing/a.log" {
		t.Errorf("got %q; want first default", got)
	}
	if exists {
		t.Error("exists = true; want false (file does not exist)")
	}
}

func TestRenderWebServerSummary(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	p := &wPrinter{w: &buf}
	renderWebServerSummary(p, []detectedWebServer{
		{Kind: "nginx", Location: "local", Unit: "nginx"},
		{Kind: "traefik", Location: "docker", Container: "traefik-proxy"},
	})
	out := buf.String()
	wantSubs := []string{
		"✓ nginx (local, systemd unit: nginx)",
		"✓ traefik (Docker container: traefik-proxy)",
		"✗ apache — not found",
		"✗ caddy — not found",
	}
	for _, s := range wantSubs {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q\nfull output:\n%s", s, out)
		}
	}
}

// TestConfirmWebServerCollectors_AcceptsLocalAndDocker covers the per-server
// confirmation loop: a local server prompts for the log path, a docker server
// is recorded directly. Both end up in the returned slice with the right parser.
func TestConfirmWebServerCollectors_AcceptsLocalAndDocker(t *testing.T) {
	t.Parallel()
	servers := []detectedWebServer{
		{
			Kind:     "nginx",
			Location: "local",
			Parser:   "nginx",
			LogPath:  "/var/log/nginx/access.log",
		},
		{
			Kind:      "traefik",
			Location:  "docker",
			Parser:    "traefik",
			Container: "traefik-proxy",
		},
	}
	// Defaults-only ask (mimics --yes).
	ask := func(_, def string) string { return def }
	askBool := func(_ string, def bool) bool { return def }
	got := confirmWebServerCollectors(ask, askBool, servers)
	if len(got) != 2 {
		t.Fatalf("expected 2 collectors, got %d: %+v", len(got), got)
	}
	if got[0].Kind != "file" || got[0].Path != "/var/log/nginx/access.log" || got[0].Parser != "nginx" {
		t.Errorf("collector[0] = %+v; want file/nginx access log", got[0])
	}
	if got[1].Kind != "docker" || got[1].Container != "traefik-proxy" || got[1].Parser != "traefik" {
		t.Errorf("collector[1] = %+v; want docker/traefik-proxy", got[1])
	}
}

// TestConfirmWebServerCollectors_DeclineSkips: answering "no" to a confirmation
// drops that server from the collector list.
func TestConfirmWebServerCollectors_DeclineSkips(t *testing.T) {
	t.Parallel()
	servers := []detectedWebServer{
		{Kind: "nginx", Location: "local", Parser: "nginx", LogPath: "/x.log"},
		{Kind: "caddy", Location: "docker", Parser: "caddy", Container: "caddy"},
	}
	ask := func(_, def string) string { return def }
	// Decline nginx, accept caddy.
	calls := 0
	askBool := func(_ string, _ bool) bool {
		calls++
		return calls != 1
	}
	got := confirmWebServerCollectors(ask, askBool, servers)
	if len(got) != 1 || got[0].Kind != "docker" || got[0].Container != "caddy" {
		t.Errorf("got %+v; want only caddy docker collector", got)
	}
}

// TestConfirmWebServerCollectors_EmptyLogPathSkipped: if the operator clears
// the log path field on a local server, no collector is recorded (config would
// fail validation otherwise).
func TestConfirmWebServerCollectors_EmptyLogPathSkipped(t *testing.T) {
	t.Parallel()
	servers := []detectedWebServer{
		{Kind: "nginx", Location: "local", Parser: "nginx", LogPath: ""},
	}
	ask := func(_, def string) string { return def } // returns "" since def is ""
	askBool := func(_ string, def bool) bool { return def }
	got := confirmWebServerCollectors(ask, askBool, servers)
	if len(got) != 0 {
		t.Errorf("expected no collectors, got %+v", got)
	}
}

// TestWriteGeneratedConfig_WithWebCollectors verifies the renderer emits one
// collectors entry per webCollector with the matching parser name, and that
// the result still passes Config validation.
func TestWriteGeneratedConfig_WithWebCollectors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	state := &wizardState{
		nftPath: "/usr/sbin/nft",
		webCollectors: []webServerCollector{
			{Kind: "file", Path: "/var/log/nginx/access.log", Parser: "nginx"},
			{Kind: "docker", Container: "traefik-proxy", Parser: "traefik"},
			{Kind: "docker", Container: "caddy-1", Parser: "caddy"},
		},
	}
	if err := writeGeneratedConfig(path, state); err != nil {
		t.Fatalf("writeGeneratedConfig: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // t.TempDir
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(data)
	wantSubs := []string{
		"kind: file",
		"path: /var/log/nginx/access.log",
		"parser: nginx",
		"kind: docker",
		"container: traefik-proxy",
		"parser: traefik",
		"container: caddy-1",
		"parser: caddy",
	}
	for _, w := range wantSubs {
		if !strings.Contains(s, w) {
			t.Errorf("config missing %q\n--- full config ---\n%s", w, s)
		}
	}
}
