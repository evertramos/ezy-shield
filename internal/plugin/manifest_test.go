// SPDX-License-Identifier: AGPL-3.0-only

package plugin

// Manifest + discovery tests (issue #207): validation table (bad perms,
// traversal, unknown type, symlinks), safe exec resolution, and discovery
// honoring the explicit allowlist.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePlugin creates plugins.d/<name>/ with a manifest and an executable.
func writePlugin(t *testing.T, root, name, manifest string, execMode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // test fixture files: modes are the SUBJECT under test
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "module.yaml"), []byte(manifest), 0o644); err != nil { //nolint:gosec // test fixture files: modes are the SUBJECT under test
		t.Fatalf("write manifest: %v", err)
	}
	execPath := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(execPath, []byte("#!/bin/sh\nexit 0\n"), execMode); err != nil { //nolint:gosec // test fixture files: modes are the SUBJECT under test
		t.Fatalf("write exec: %v", err)
	}
	// WriteFile's mode is masked by umask; pin the exact bits explicitly
	// (the world-writable case depends on them).
	if err := os.Chmod(execPath, execMode); err != nil { //nolint:gosec // test fixture files: modes are the SUBJECT under test
		t.Fatalf("chmod exec: %v", err)
	}
	return dir
}

func validManifest(name string) string {
	return "name: " + name + "\nversion: 1.0.0\ntype: parser\nexec: run.sh\nmatches: [custom-app]\n"
}

func TestLoadManifest_Valid(t *testing.T) {
	root := t.TempDir()
	dir := writePlugin(t, root, "demo", validManifest("demo")+"network: none\ntimeout: 10s\n", 0o755)

	m, err := LoadManifest(dir)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if m.Name != "demo" || m.Type != "parser" || m.RequestTimeout() != 10e9 {
		t.Errorf("manifest = %+v", m)
	}
	if m.ResolvedExec != filepath.Join(dir, "run.sh") {
		t.Errorf("resolved exec = %s", m.ResolvedExec)
	}
	if len(m.Network.Hosts) != 0 {
		t.Errorf("network none must resolve to no hosts")
	}
}

func TestLoadManifest_NetworkHosts(t *testing.T) {
	root := t.TempDir()
	dir := writePlugin(t, root, "net", validManifest("net")+"network: [api.example.com]\n", 0o755)
	m, err := LoadManifest(dir)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(m.Network.Hosts) != 1 || m.Network.Hosts[0] != "api.example.com" {
		t.Errorf("network hosts = %v", m.Network.Hosts)
	}
}

func TestLoadManifest_ValidationTable(t *testing.T) {
	root := t.TempDir()
	cases := map[string]struct {
		manifest string
		execMode os.FileMode
		wantErr  string
	}{
		"unknown type": {
			"name: p1\nversion: 1\ntype: enforcer\nexec: run.sh\n", 0o755,
			"'type' must be parser or notifier",
		},
		"bad name": {
			"name: ../Evil\nversion: 1\ntype: notifier\nexec: run.sh\n", 0o755,
			"'name' is required",
		},
		"traversal exec": {
			"name: p3\nversion: 1\ntype: notifier\nexec: ../../../bin/sh\n", 0o755,
			"escapes the plugin directory",
		},
		"absolute exec": {
			"name: p4\nversion: 1\ntype: notifier\nexec: /bin/sh\n", 0o755,
			"no absolute paths",
		},
		"world-writable exec": {
			"name: p5\nversion: 1\ntype: notifier\nexec: run.sh\n", 0o777,
			"world-writable",
		},
		"non-executable": {
			"name: p6\nversion: 1\ntype: notifier\nexec: run.sh\n", 0o644,
			"not executable",
		},
		"parser without matches": {
			"name: p7\nversion: 1\ntype: parser\nexec: run.sh\n", 0o755,
			"at least one 'matches'",
		},
		"matches on notifier": {
			"name: p8\nversion: 1\ntype: notifier\nexec: run.sh\nmatches: [x]\n", 0o755,
			"parser plugins only",
		},
		"timeout above hard max": {
			"name: p9\nversion: 1\ntype: notifier\nexec: run.sh\ntimeout: 5m\n", 0o755,
			"exceeds the hard maximum",
		},
		"unknown manifest field": {
			"name: p10\nversion: 1\ntype: notifier\nexec: run.sh\nsudo: true\n", 0o755,
			"field sudo not found",
		},
	}
	i := 0
	for name, tc := range cases {
		i++
		dir := writePlugin(t, root, "case"+string(rune('a'+i)), tc.manifest, tc.execMode)
		_, err := LoadManifest(dir)
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error %q does not contain %q", name, err, tc.wantErr)
		}
	}
}

func TestLoadManifest_SymlinkExecRejected(t *testing.T) {
	root := t.TempDir()
	dir := writePlugin(t, root, "sym", "name: sym\nversion: 1\ntype: notifier\nexec: link.sh\n", 0o755)
	if err := os.Symlink("/bin/sh", filepath.Join(dir, "link.sh")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	_, err := LoadManifest(dir)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked exec must be rejected, got %v", err)
	}
}

func TestLoadManifest_WorldWritableManifestRejected(t *testing.T) {
	root := t.TempDir()
	dir := writePlugin(t, root, "ww", validManifest("ww"), 0o755)
	if err := os.Chmod(filepath.Join(dir, "module.yaml"), 0o666); err != nil { //nolint:gosec // test fixture files: modes are the SUBJECT under test
		t.Fatalf("chmod: %v", err)
	}
	_, err := LoadManifest(dir)
	if err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("world-writable manifest must be rejected, got %v", err)
	}
}

func TestDiscover_HonorsAllowlist(t *testing.T) {
	root := t.TempDir()
	writePlugin(t, root, "alpha", validManifest("alpha"), 0o755)
	writePlugin(t, root, "beta", validManifest("beta"), 0o755)
	writePlugin(t, root, "broken", "name: broken\ntype: wat\n", 0o755)
	// Manifest name mismatching its directory is invalid — an allowlisted
	// name must not be satisfiable by a differently-named directory.
	writePlugin(t, root, "mismatch", validManifest("othername"), 0o755)

	found, err := Discover(root, []string{"alpha", "ghost"})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	status := map[string]string{}
	for _, d := range found {
		status[d.Name] = d.Status
	}
	if status["alpha"] != StatusReady {
		t.Errorf("alpha = %s, want ready", status["alpha"])
	}
	if status["beta"] != StatusNotAllowed {
		t.Errorf("beta = %s, want not-allowed (valid but not in allow[])", status["beta"])
	}
	if status["broken"] != StatusInvalid {
		t.Errorf("broken = %s, want invalid", status["broken"])
	}
	if status["mismatch"] != StatusInvalid {
		t.Errorf("mismatch = %s, want invalid (name/dir mismatch)", status["mismatch"])
	}
}

func TestDiscover_MissingDirIsEmpty(t *testing.T) {
	found, err := Discover(filepath.Join(t.TempDir(), "absent"), nil)
	if err != nil || len(found) != 0 {
		t.Fatalf("missing dir: found=%v err=%v", found, err)
	}
}
