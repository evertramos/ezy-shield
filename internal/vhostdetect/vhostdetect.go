// Package vhostdetect enumerates virtual-host domains served by local
// reverse-proxy setups so the init wizard can offer to configure the
// matching edge enforcer. It targets the nginx-proxy convention first
// (containers labelled with env VIRTUAL_HOST=domain1,domain2,…), which
// covers the dogfood host that surfaced issue #43.
//
// The package deliberately shells out to the `docker` CLI rather than
// dialing the Engine API directly: it matches the existing pattern in
// cmd/ezyshield/init.go (detectDockerContainers) and keeps the wizard
// dependency-free. Docker not being installed / running is a normal path —
// callers get an empty slice and continue the wizard.
//
// Nothing here writes state, opens a socket, or requires root beyond
// whatever the wrapping wizard already needed. `docker ps` inherits the
// caller's Docker group membership.
package vhostdetect

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"
)

// DockerCLI abstracts the small piece of the `docker` CLI vhostdetect needs.
// Production wires it to a real exec.CommandContext; tests plug in a fake
// that returns canned output.
type DockerCLI interface {
	// Ps returns the raw stdout of `docker ps --format <format>` (or
	// equivalent). One line per container. Returns an error if the CLI
	// isn't runnable — callers treat that as "Docker not available" and
	// move on rather than failing the wizard.
	Ps(ctx context.Context, format string) (string, error)
	// Inspect returns the raw stdout of `docker inspect --format <format>
	// <container>` for a single container. The format template extracts
	// the fields we need (env vars). Errors are returned so callers can
	// distinguish "container gone" from "docker gone" upstream.
	Inspect(ctx context.Context, container, format string) (string, error)
}

// realCLI is the production DockerCLI backed by the docker binary.
type realCLI struct{}

// DefaultCLI returns a DockerCLI that shells out to `docker`. Timeouts are
// caller-controlled via ctx.
func DefaultCLI() DockerCLI { return realCLI{} }

// Ps shells out to `docker ps` and returns its raw stdout.
func (realCLI) Ps(ctx context.Context, format string) (string, error) {
	//nolint:gosec // fixed binary; format string is a literal from this package
	out, err := exec.CommandContext(ctx, "docker", "ps", "--format", format).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Inspect shells out to `docker inspect --format` for a single container.
func (realCLI) Inspect(ctx context.Context, container, format string) (string, error) {
	//nolint:gosec // fixed binary; container is a Docker-provided name we
	// just enumerated from `docker ps`, not user input; format is a literal.
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", format, container).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// VHost is one detection hit: a container (or local config directory) that
// exposes one or more virtual-host domains.
type VHost struct {
	Container string   // container name, or config directory for file sources
	Image     string   // image ref (for display only; empty for file sources)
	Domains   []string // detected domains, trimmed & non-empty
	// Source names the detection convention that produced this entry
	// (issue #488). Zero value ("") predates the field and means docker-env.
	Source Source
}

// DefaultTimeout bounds one Detect call end-to-end when the caller passes
// context.Background(). Kept short: the wizard is interactive.
const DefaultTimeout = 8 * time.Second

// Detect returns every container whose environment includes VIRTUAL_HOST
// with at least one non-empty domain. Best-effort: Docker not available,
// no containers, or a per-container inspect failure all short-circuit to
// an empty (or partial) slice and a nil error. Only a wholly unexpected
// error propagates.
//
// The caller is responsible for the top-level ctx timeout. When ctx has no
// deadline, Detect adds one of DefaultTimeout so a stuck `docker` process
// can never wedge the wizard.
func Detect(ctx context.Context, cli DockerCLI) ([]VHost, error) {
	if cli == nil {
		cli = DefaultCLI()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	// The format is a tab-separated "<name>\t<image>" so we can split
	// safely even on images that contain '/' (library/nginx).
	raw, err := cli.Ps(ctx, "{{.Names}}\t{{.Image}}")
	if err != nil {
		// Docker not installed / not running / non-zero exit → not an
		// error the wizard should surface. Return an empty slice and let
		// the caller decide to skip the whole CDN step.
		return nil, nil //nolint:nilerr // intentional: docker down != wizard failure
	}
	names := parsePsOutput(raw)
	out := make([]VHost, 0, len(names))
	for _, n := range names {
		out = append(out, inspectContainer(ctx, cli, n)...)
	}
	return out, nil
}

// psRow is one line of `docker ps --format {{.Names}}\t{{.Image}}`.
type psRow struct {
	Name  string
	Image string
}

// parsePsOutput turns the multi-line `docker ps` output into rows. Empty
// lines are ignored. Any line missing the tab separator is dropped (a
// legitimate container name never contains a tab).
func parsePsOutput(raw string) []psRow {
	var out []psRow
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		name, image, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		image = strings.TrimSpace(image)
		if name == "" {
			continue
		}
		out = append(out, psRow{Name: name, Image: image})
	}
	return out
}

// inspectContainer asks Docker for the container's env vars AND labels via a
// Go template — one KEY=value per line — then extracts VIRTUAL_HOST
// (nginx-proxy convention) and Traefik router rule labels (issue #488).
// Returns zero, one, or two VHost entries (one per matching convention);
// inspect failures yield none.
func inspectContainer(ctx context.Context, cli DockerCLI, row psRow) []VHost {
	raw, err := cli.Inspect(ctx, row.Name,
		"{{range .Config.Env}}{{println .}}{{end}}"+
			"{{range $k, $v := .Config.Labels}}{{printf \"%s=%s\\n\" $k $v}}{{end}}")
	if err != nil {
		return nil
	}
	// Fallback used purely to satisfy tests: some cases pass rows built
	// without the ps step.
	if row.Name == "" {
		return nil
	}
	var out []VHost
	if domains := extractVirtualHost(raw); len(domains) > 0 {
		out = append(out, VHost{
			Container: row.Name, Image: row.Image,
			Domains: domains, Source: SourceDockerEnv,
		})
	}
	if domains := extractTraefikLabelDomains(raw); len(domains) > 0 {
		out = append(out, VHost{
			Container: row.Name, Image: row.Image,
			Domains: domains, Source: SourceTraefikDocker,
		})
	}
	return out
}

// extractVirtualHost scans docker-inspect env output for VIRTUAL_HOST=…
// The nginx-proxy convention allows comma-separated multiple domains.
// Whitespace around each domain is trimmed and empty segments dropped.
// Domain values are otherwise passed through unchanged — validation of
// what constitutes a "real" domain (e.g. FQDN vs local hostname) is the
// resolver's job.
func extractVirtualHost(env string) []string {
	sc := bufio.NewScanner(strings.NewReader(env))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) != "VIRTUAL_HOST" {
			continue
		}
		return splitDomains(val)
	}
	return nil
}

// splitDomains splits a VIRTUAL_HOST value on ',' and trims whitespace.
// A leading/trailing dot, wildcard prefix ("*.example.com"), or empty
// segment is dropped — those aren't resolvable and would waste a DNS
// round-trip if we forwarded them.
func splitDomains(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var out []string
	for _, p := range parts {
		d := strings.TrimSpace(p)
		if d == "" || strings.HasPrefix(d, "*") || strings.HasPrefix(d, ".") {
			continue
		}
		out = append(out, d)
	}
	return out
}

// AllDomains flattens the VHost slice to a deduplicated list of domains,
// preserving first-seen order. Handy for feeding cdndetect.MatchDomains
// without the caller having to dedup manually.
func AllDomains(vhosts []VHost) []string {
	seen := make(map[string]bool)
	var out []string
	for _, vh := range vhosts {
		for _, d := range vh.Domains {
			if seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}
