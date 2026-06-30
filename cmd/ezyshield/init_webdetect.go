package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// detectedWebServer is one running instance of a web server discovered by the
// init wizard. The wizard offers to add one collector per entry.
//
// For Location == "local", LogPath holds the access-log path that will be
// proposed in the prompt. LogExists records whether that file currently
// exists on disk, used only for the summary display.
// For Location == "docker", Container/Image hold the running container.
type detectedWebServer struct {
	Kind      string // nginx | apache | traefik | caddy
	Location  string // local | docker
	Parser    string // parser name written to config.yaml
	LogPath   string
	LogExists bool
	Unit      string
	Container string
	Image     string
}

// webServerCollector is the operator-approved outcome of the wizard prompt
// for one detected web server. It is rendered directly into config.yaml.
type webServerCollector struct {
	Kind      string // file | docker
	Path      string // for kind=file
	Container string // for kind=docker
	Parser    string
}

// webServerSpec describes how to detect one kind of web server.
type webServerSpec struct {
	kind     string
	parser   string
	units    []string // candidate systemd units (first active wins)
	logPaths []string // candidate access log paths (first existing wins)
	keywords []string // image/container name keywords for docker detection
}

// webServerSpecs is the canonical detection table. Add a new entry here when
// extending detection to a new web server (also add a parser to
// validParserNames in internal/config).
var webServerSpecs = []webServerSpec{
	{
		kind:     "nginx",
		parser:   "nginx",
		units:    []string{"nginx"},
		logPaths: []string{"/var/log/nginx/access.log"},
		keywords: []string{"nginx"},
	},
	{
		kind:   "apache",
		parser: "apache",
		units:  []string{"apache2", "httpd"},
		logPaths: []string{
			"/var/log/apache2/access.log",
			"/var/log/httpd/access_log",
		},
		keywords: []string{"apache", "httpd"},
	},
	{
		kind:     "traefik",
		parser:   "traefik",
		units:    []string{"traefik"},
		logPaths: []string{"/var/log/traefik/access.log"},
		keywords: []string{"traefik"},
	},
	{
		kind:     "caddy",
		parser:   "caddy",
		units:    []string{"caddy"},
		logPaths: []string{"/var/log/caddy/access.log"},
		keywords: []string{"caddy"},
	},
}

// specForKind returns the webServerSpec matching kind.
func specForKind(kind string) (webServerSpec, bool) {
	for _, s := range webServerSpecs {
		if s.kind == kind {
			return s, true
		}
	}
	return webServerSpec{}, false
}

// resolveLocalLogPath returns the first existing path in spec.logPaths, or
// spec.logPaths[0] if none exist. The second return reports whether the
// returned path exists on disk.
func resolveLocalLogPath(spec webServerSpec) (string, bool) {
	for _, p := range spec.logPaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
	}
	if len(spec.logPaths) == 0 {
		return "", false
	}
	return spec.logPaths[0], false
}

// systemctlIsActive reports whether systemctl considers unit active. systemctl
// exits non-zero for inactive/failed/missing units, so a non-nil error reliably
// means "not active".
func systemctlIsActive(ctx context.Context, unit string) bool {
	//nolint:gosec // unit names come from webServerSpecs, never from log/user input
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

// detectLocalWebServers returns one entry per locally-running web server, as
// reported by systemctl. Each kind appears at most once (first active unit wins).
// Returns nil when systemctl is unavailable (non-systemd hosts).
func detectLocalWebServers() []detectedWebServer {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out []detectedWebServer
	for _, spec := range webServerSpecs {
		var unit string
		for _, u := range spec.units {
			if systemctlIsActive(ctx, u) {
				unit = u
				break
			}
		}
		if unit == "" {
			continue
		}
		logPath, exists := resolveLocalLogPath(spec)
		out = append(out, detectedWebServer{
			Kind:      spec.kind,
			Location:  "local",
			Parser:    spec.parser,
			LogPath:   logPath,
			LogExists: exists,
			Unit:      unit,
		})
	}
	return out
}

// identifyDockerWebServer returns the matching webServerSpec.kind for c, or
// "" if no keyword matches.
func identifyDockerWebServer(c dockerContainer) string {
	name := strings.ToLower(c.name)
	image := strings.ToLower(c.image)
	for _, spec := range webServerSpecs {
		for _, kw := range spec.keywords {
			if strings.Contains(name, kw) || strings.Contains(image, kw) {
				return spec.kind
			}
		}
	}
	return ""
}

// detectDockerWebServers returns one entry per running container that matches
// a known web server keyword in its name or image. The container list is the
// same data already gathered for the rest of the wizard; passing nil (Docker
// not installed) returns nil.
func detectDockerWebServers(containers []dockerContainer) []detectedWebServer {
	var out []detectedWebServer
	for _, c := range containers {
		kind := identifyDockerWebServer(c)
		if kind == "" {
			continue
		}
		spec, ok := specForKind(kind)
		if !ok {
			continue
		}
		out = append(out, detectedWebServer{
			Kind:      kind,
			Location:  "docker",
			Parser:    spec.parser,
			Container: c.name,
			Image:     c.image,
		})
	}
	return out
}

// detectWebServers runs local + docker detection and returns the combined list.
// Local entries always appear first to keep the summary order stable.
func detectWebServers(containers []dockerContainer) []detectedWebServer {
	out := detectLocalWebServers()
	out = append(out, detectDockerWebServers(containers)...)
	return out
}

// renderWebServerSummary prints "✓ kind ..." / "✗ kind — not found" lines for
// every known kind, in webServerSpecs order, so the operator sees a complete
// detection report.
func renderWebServerSummary(p *wPrinter, detected []detectedWebServer) {
	have := map[string][]detectedWebServer{}
	for _, ws := range detected {
		have[ws.Kind] = append(have[ws.Kind], ws)
	}
	for _, spec := range webServerSpecs {
		entries := have[spec.kind]
		if len(entries) == 0 {
			p.printf("  ✗ %s — not found\n", spec.kind)
			continue
		}
		for _, e := range entries {
			switch e.Location {
			case "local":
				p.printf("  ✓ %s (local, systemd unit: %s)\n", e.Kind, e.Unit)
			case "docker":
				p.printf("  ✓ %s (Docker container: %s)\n", e.Kind, e.Container)
			}
		}
	}
}
