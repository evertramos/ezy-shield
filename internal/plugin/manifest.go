// SPDX-License-Identifier: AGPL-3.0-only

package plugin

// Module manifest + discovery (issue #207). A plugin ships as
// /etc/ezyshield/plugins.d/<name>/module.yaml plus its executable.
// Executing operator-provided binaries is the single most dangerous
// feature in the daemon, so everything here fails closed:
//
//   - plugins run ONLY when plugins.enabled: true AND the plugin's name
//     is in plugins.allow[] — dropping a file into plugins.d is never
//     enough to execute code;
//   - exec is a RELATIVE path resolved against the plugin's own dir: no
//     PATH lookup, no absolute paths, no traversal, no symlinks;
//   - the executable and the manifest must be regular files, not
//     world-writable, owned by root or by the plugin dir's owner.
//
// The network declaration is ADVISORY in v1 — no namespace isolation is
// applied yet; the field exists so v2 can enforce it, and the docs say so
// honestly.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPluginsDir is scanned for plugin subdirectories.
const DefaultPluginsDir = "/etc/ezyshield/plugins.d"

// manifestFileName is the fixed per-plugin manifest name.
const manifestFileName = "module.yaml"

// validPluginTypes is the closed type vocabulary for v1.
var validPluginTypes = map[string]bool{"parser": true, "notifier": true}

var pluginNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// NetworkDecl is the manifest's network declaration: the scalar "none"
// (the default) or a list of hostnames the plugin says it talks to.
// ADVISORY in v1 — documented, not enforced.
type NetworkDecl struct {
	// Hosts is empty for "none".
	Hosts []string
}

// UnmarshalYAML accepts `network: none` or `network: [host, ...]`.
func (n *NetworkDecl) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Value != "none" {
			return fmt.Errorf("line %d: network must be \"none\" or a list of hostnames, got %q", value.Line, value.Value)
		}
		n.Hosts = nil
		return nil
	case yaml.SequenceNode:
		return value.Decode(&n.Hosts)
	default:
		return fmt.Errorf("line %d: network must be \"none\" or a list of hostnames", value.Line)
	}
}

// Manifest is one parsed, validated module.yaml.
type Manifest struct {
	Name    string      `yaml:"name"`
	Version string      `yaml:"version"`
	Type    string      `yaml:"type"`
	Exec    string      `yaml:"exec"`
	Matches []string    `yaml:"matches"`
	Network NetworkDecl `yaml:"network"`
	// Timeout overrides the per-request timeout (Go duration string).
	// Clamped by validation to (0, MaxRequestTimeout].
	Timeout manifestDuration `yaml:"timeout"`

	// ResolvedExec is the absolute executable path after safe resolution
	// against the plugin dir. Set by LoadManifest, never from YAML.
	ResolvedExec string `yaml:"-"`
	// Dir is the plugin directory the manifest came from.
	Dir string `yaml:"-"`
}

// LoadManifest reads and strictly validates <dir>/module.yaml, including
// the filesystem checks on the manifest and the executable.
func LoadManifest(dir string) (*Manifest, error) {
	path := filepath.Join(dir, manifestFileName)
	if err := checkFileSafety(path, false); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-owned plugins.d content, gated by the allowlist
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	m.Dir = dir
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := m.resolveExec(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// validate applies the schema rules (filesystem checks live in
// resolveExec/checkFileSafety).
func (m *Manifest) validate() error {
	if !pluginNameRE.MatchString(m.Name) {
		return fmt.Errorf("'name' is required and must match %s", pluginNameRE)
	}
	if m.Version == "" {
		return fmt.Errorf("'version' is required")
	}
	if !validPluginTypes[m.Type] {
		return fmt.Errorf("'type' must be parser or notifier, got %q", m.Type)
	}
	if m.Exec == "" {
		return fmt.Errorf("'exec' is required")
	}
	if m.Type == "parser" && len(m.Matches) == 0 {
		return fmt.Errorf("parser plugins must declare at least one 'matches' entry")
	}
	if m.Type != "parser" && len(m.Matches) > 0 {
		return fmt.Errorf("'matches' applies to parser plugins only")
	}
	if time.Duration(m.Timeout) < 0 {
		return fmt.Errorf("'timeout' must be positive")
	}
	if time.Duration(m.Timeout) > MaxRequestTimeout {
		return fmt.Errorf("'timeout' %s exceeds the hard maximum %s", time.Duration(m.Timeout), MaxRequestTimeout)
	}
	return nil
}

// RequestTimeout returns the effective per-request timeout for this
// plugin (zero = runtime default).
func (m *Manifest) RequestTimeout() time.Duration { return time.Duration(m.Timeout) }

// manifestDuration parses Go duration strings ("5s") from YAML.
type manifestDuration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *manifestDuration) UnmarshalYAML(value *yaml.Node) error {
	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q: %v", value.Line, value.Value, err)
	}
	*d = manifestDuration(dur)
	return nil
}

// resolveExec resolves Exec against the plugin dir ONLY: relative paths,
// no traversal, no absolute paths, no PATH lookup — and the resolved file
// must pass the same safety checks as the manifest, plus be executable
// and not a symlink (a symlink could re-point outside the dir after
// validation).
func (m *Manifest) resolveExec() error {
	if filepath.IsAbs(m.Exec) {
		return fmt.Errorf("'exec' must be relative to the plugin directory (no absolute paths)")
	}
	cleaned := filepath.Clean(m.Exec)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return fmt.Errorf("'exec' escapes the plugin directory")
	}
	resolved := filepath.Join(m.Dir, cleaned)
	if err := checkFileSafety(resolved, true); err != nil {
		return fmt.Errorf("'exec' %s: %w", m.Exec, err)
	}
	m.ResolvedExec = resolved
	return nil
}

// checkFileSafety enforces the shared file rules: regular file (symlinks
// rejected via Lstat), not world-writable, owned by root or by the owner
// of its containing directory; executables additionally need an exec bit.
func checkFileSafety(path string, wantExec bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("must not be a symlink")
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("must be a regular file (mode %s)", fi.Mode())
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("is world-writable (mode %s) — refuse to trust it", fi.Mode().Perm())
	}
	if wantExec && fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("is not executable (mode %s)", fi.Mode().Perm())
	}
	return checkFileOwner(path, fi)
}

// ── Discovery ────────────────────────────────────────────────────────────────

// Status values for discovered plugins.
const (
	StatusReady      = "ready"       // valid manifest, allowlisted
	StatusNotAllowed = "not-allowed" // valid manifest, absent from plugins.allow
	StatusInvalid    = "invalid"     // manifest failed validation
)

// Discovered is one plugins.d entry as seen by discovery.
type Discovered struct {
	Dir      string
	Name     string // dir basename (manifest name when valid)
	Manifest *Manifest
	Status   string
	Err      error // set when Status == StatusInvalid
}

// Discover scans pluginsDir for <name>/module.yaml entries and classifies
// each against the allowlist. It never executes anything. A missing
// pluginsDir yields an empty result, not an error.
func Discover(pluginsDir string, allow []string) ([]Discovered, error) {
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("plugin: read %s: %w", pluginsDir, err)
	}
	allowed := make(map[string]bool, len(allow))
	for _, a := range allow {
		allowed[a] = true
	}

	var out []Discovered
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(pluginsDir, e.Name())
		if _, err := os.Stat(filepath.Join(dir, manifestFileName)); err != nil {
			continue // not a plugin dir
		}
		d := Discovered{Dir: dir, Name: e.Name()}
		m, err := LoadManifest(dir)
		switch {
		case err != nil:
			d.Status, d.Err = StatusInvalid, err
		case m.Name != e.Name():
			d.Status = StatusInvalid
			d.Err = fmt.Errorf("manifest name %q does not match directory %q", m.Name, e.Name())
		case !allowed[m.Name]:
			// The allowlist is by NAME, checked against the validated
			// manifest — dropping files in the dir is never enough.
			d.Manifest, d.Status = m, StatusNotAllowed
		default:
			d.Manifest, d.Status = m, StatusReady
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
