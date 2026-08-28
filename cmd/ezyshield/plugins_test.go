// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for `ezyshield plugins` (issue #207): list honoring the config
// gate + allowlist, validate's manifest + handshake dry-run, and the
// doctor integration.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pluginFixtureScript speaks just enough tier-1 protocol for a handshake
// dry-run: read the daemon hello, answer, then wait for stdin EOF.
const pluginFixtureScript = `#!/bin/sh
read -r _hello
printf '{"protocol_version":1,"name":"demo","version":"0.1.0","capabilities":["parse"]}\n'
cat >/dev/null
`

func writeTestPlugin(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // test fixture files: modes are the SUBJECT under test
		t.Fatalf("mkdir: %v", err)
	}
	manifest := "name: " + name + "\nversion: 0.1.0\ntype: parser\nexec: run.sh\nmatches: [demo-log]\n"
	if err := os.WriteFile(filepath.Join(dir, "module.yaml"), []byte(manifest), 0o644); err != nil { //nolint:gosec // test fixture files: modes are the SUBJECT under test
		t.Fatalf("manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte(pluginFixtureScript), 0o755); err != nil { //nolint:gosec // test fixture files: modes are the SUBJECT under test
		t.Fatalf("exec: %v", err)
	}
	return dir
}

func runPluginsCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	jsonOutput = false
	t.Cleanup(func() { jsonOutput = false })
	root := newRootCmd()
	var out strings.Builder
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"plugins"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestPluginsList_StatusesAndGate(t *testing.T) {
	dir := t.TempDir()
	pluginsDir := filepath.Join(dir, "plugins.d")
	writeTestPlugin(t, pluginsDir, "demo")
	writeTestPlugin(t, pluginsDir, "extra")

	cfgPath := writeFile(t, dir, "config.yaml",
		"data_dir: /tmp\nplugins:\n  enabled: true\n  dir: "+pluginsDir+"\n  allow: [demo]\n")

	out, err := runPluginsCLI(t, "list", "--config", cfgPath, "--json")
	if err != nil {
		t.Fatalf("plugins list: %v\n%s", err, out)
	}
	var doc struct {
		Enabled bool        `json:"enabled"`
		Plugins []pluginRow `json:"plugins"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if !doc.Enabled || len(doc.Plugins) != 2 {
		t.Fatalf("doc = %+v", doc)
	}
	byName := map[string]pluginRow{}
	for _, p := range doc.Plugins {
		byName[p.Name] = p
	}
	if byName["demo"].Status != "ready" || byName["demo"].Version != "0.1.0" {
		t.Errorf("demo = %+v", byName["demo"])
	}
	if byName["extra"].Status != "not-allowed" {
		t.Errorf("extra = %+v (allowlist must gate by name)", byName["extra"])
	}
}

func TestPluginsList_DisabledSystemDowngradesReady(t *testing.T) {
	dir := t.TempDir()
	pluginsDir := filepath.Join(dir, "plugins.d")
	writeTestPlugin(t, pluginsDir, "demo")
	cfgPath := writeFile(t, dir, "config.yaml",
		"data_dir: /tmp\nplugins:\n  enabled: false\n  dir: "+pluginsDir+"\n  allow: [demo]\n")

	out, err := runPluginsCLI(t, "list", "--config", cfgPath)
	if err != nil {
		t.Fatalf("plugins list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "disabled") {
		t.Errorf("disabled gate must be visible:\n%s", out)
	}
}

func TestPluginsValidate_HandshakeDryRun(t *testing.T) {
	pluginsDir := t.TempDir()
	dir := writeTestPlugin(t, pluginsDir, "demo")

	out, err := runPluginsCLI(t, "validate", dir)
	if err != nil {
		t.Fatalf("plugins validate: %v\n%s", err, out)
	}
	if !strings.Contains(out, "manifest valid: demo v0.1.0 (parser)") ||
		!strings.Contains(out, "handshake OK: demo v0.1.0") {
		t.Errorf("output:\n%s", out)
	}
}

func TestPluginsValidate_BadManifestFails(t *testing.T) {
	pluginsDir := t.TempDir()
	dir := writeTestPlugin(t, pluginsDir, "demo")
	//nolint:gosec // test fixture files: modes are the SUBJECT under test
	if err := os.WriteFile(filepath.Join(dir, "module.yaml"),
		[]byte("name: demo\nversion: 1\ntype: wat\nexec: run.sh\n"), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if out, err := runPluginsCLI(t, "validate", dir); err == nil {
		t.Fatalf("invalid manifest must fail validate, got:\n%s", out)
	}
}

func TestDoctorPlugins_Checks(t *testing.T) {
	dir := t.TempDir()
	pluginsDir := filepath.Join(dir, "plugins.d")
	writeTestPlugin(t, pluginsDir, "demo")
	brokenDir := filepath.Join(pluginsDir, "broken")
	if err := os.MkdirAll(brokenDir, 0o755); err != nil { //nolint:gosec // test fixture files: modes are the SUBJECT under test
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(brokenDir, "module.yaml"), []byte("name: broken\ntype: nope\n"), 0o644); err != nil { //nolint:gosec // test fixture files: modes are the SUBJECT under test
		t.Fatalf("write: %v", err)
	}

	// Disabled system → single N/A.
	writeFile(t, dir, "config.yaml", "data_dir: /tmp\n")
	if res := checkPlugins(dir); len(res) != 1 || res[0].Status != statusNA {
		t.Fatalf("disabled: %+v", res)
	}

	// Enabled: demo passes, broken warns, ghost (allowlisted, missing) warns.
	writeFile(t, dir, "config2.yaml", "") // placeholder to avoid name clash confusion
	cfg := "data_dir: /tmp\nplugins:\n  enabled: true\n  dir: " + pluginsDir + "\n  allow: [demo, ghost]\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o644); err != nil { //nolint:gosec // test fixture files: modes are the SUBJECT under test
		t.Fatalf("rewrite config: %v", err)
	}
	res := checkPlugins(dir)
	got := map[string]string{}
	hints := map[string]string{}
	for _, r := range res {
		got[r.Name] = r.Status
		hints[r.Name] = r.Hint
	}
	if got["plugins: demo"] != statusPass {
		t.Errorf("demo: %+v", res)
	}
	if got["plugins: broken"] != statusWarn || !strings.Contains(hints["plugins: broken"], "manifest invalid") {
		t.Errorf("broken: %+v", res)
	}
	if got["plugins: ghost"] != statusWarn || !strings.Contains(hints["plugins: ghost"], "no such plugin directory") {
		t.Errorf("ghost: %+v", res)
	}
}
