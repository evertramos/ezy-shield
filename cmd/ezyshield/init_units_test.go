// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/configs"
)

// Regression tests for issue #449: on a .deb/.rpm install the wizard used to
// copy its embedded units (ExecStart=/usr/local/bin/...) into
// /etc/systemd/system, shadowing the packaged units and crash-looping both
// services with status=203/EXEC.

// testUnitDeps returns deps rooted in fresh temp dirs with resolution hooks
// that fail (individual tests override what they need).
func testUnitDeps(t *testing.T) unitInstallDeps {
	t.Helper()
	return unitInstallDeps{
		etcUnitDir: t.TempDir(),
		pkgUnitDir: t.TempDir(),
		execPath:   func() (string, error) { return "", errors.New("unavailable") },
		lookPath:   func(string) (string, error) { return "", errors.New("not found") },
	}
}

func writeTestUnit(t *testing.T, path, execStart string) {
	t.Helper()
	content := "[Unit]\nDescription=test\n[Service]\nExecStart=" + execStart + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // test file
		t.Fatalf("writing %s: %v", path, err)
	}
}

// etcUnitNames lists the ezyshield unit files present in dir.
func etcUnitNames(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	for _, unit := range shadowUnitNames {
		if _, err := os.Stat(filepath.Join(dir, unit)); err == nil {
			out = append(out, unit)
		}
	}
	return out
}

func TestInstallSystemdUnits_PackageInstall_WritesNothing(t *testing.T) {
	d := testUnitDeps(t)
	writeTestUnit(t, filepath.Join(d.pkgUnitDir, "ezyshield.service"), "/usr/bin/ezyshield run")
	writeTestUnit(t, filepath.Join(d.pkgUnitDir, "ezyshield-enforcer.service"), "/usr/bin/ezyshield-enforcer")

	var out bytes.Buffer
	if err := installSystemdUnitsWith(&out, d); err != nil {
		t.Fatalf("installSystemdUnitsWith: %v", err)
	}
	if got := etcUnitNames(t, d.etcUnitDir); len(got) != 0 {
		t.Errorf("package install wrote units into the etc dir: %v", got)
	}
	if !strings.Contains(out.String(), "packaged systemd units") {
		t.Errorf("output does not say the packaged units are used:\n%s", out.String())
	}
}

func TestInstallSystemdUnits_PackageInstall_RemovesBrokenOverride(t *testing.T) {
	d := testUnitDeps(t)
	writeTestUnit(t, filepath.Join(d.pkgUnitDir, "ezyshield.service"), "/usr/bin/ezyshield run")

	// The broken state this bug shipped: overrides whose ExecStart points at
	// a binary that does not exist.
	missing := filepath.Join(t.TempDir(), "no-such-dir", "ezyshield")
	writeTestUnit(t, filepath.Join(d.etcUnitDir, "ezyshield.service"), missing+" run")
	writeTestUnit(t, filepath.Join(d.etcUnitDir, "ezyshield-enforcer.service"), missing+"-enforcer")

	var out bytes.Buffer
	if err := installSystemdUnitsWith(&out, d); err != nil {
		t.Fatalf("installSystemdUnitsWith: %v", err)
	}
	if got := etcUnitNames(t, d.etcUnitDir); len(got) != 0 {
		t.Errorf("broken overrides were not removed: %v", got)
	}
	if !strings.Contains(out.String(), "removed stale unit override") {
		t.Errorf("output does not report the removal:\n%s", out.String())
	}
}

func TestInstallSystemdUnits_PackageInstall_KeepsWorkingOverride(t *testing.T) {
	d := testUnitDeps(t)
	writeTestUnit(t, filepath.Join(d.pkgUnitDir, "ezyshield.service"), "/usr/bin/ezyshield run")

	// A deliberate admin override: ExecStart points at a binary that exists.
	binDir := t.TempDir()
	adminBin := filepath.Join(binDir, "ezyshield")
	if err := os.WriteFile(adminBin, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // test file
		t.Fatalf("writing admin binary: %v", err)
	}
	override := filepath.Join(d.etcUnitDir, "ezyshield.service")
	writeTestUnit(t, override, adminBin+" run")

	var out bytes.Buffer
	if err := installSystemdUnitsWith(&out, d); err != nil {
		t.Fatalf("installSystemdUnitsWith: %v", err)
	}
	if _, err := os.Stat(override); err != nil {
		t.Errorf("working admin override was removed: %v", err)
	}
	if !strings.Contains(out.String(), "left in place") {
		t.Errorf("output does not warn about the kept override:\n%s", out.String())
	}
}

func TestInstallSystemdUnits_PackageInstall_DropIn(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantRemoved bool
	}{
		{"exact wizard content is removed", envDropInContent(), true},
		{"edited content is the admin's and stays", "[Service]\nEnvironmentFile=-/etc/ezyshield/.env\nNice=5\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := testUnitDeps(t)
			writeTestUnit(t, filepath.Join(d.pkgUnitDir, "ezyshield.service"), "/usr/bin/ezyshield run")
			dropInDir := filepath.Join(d.etcUnitDir, "ezyshield.service.d")
			if err := os.MkdirAll(dropInDir, 0o750); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			path := filepath.Join(dropInDir, "env.conf")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil { //nolint:gosec // test file
				t.Fatalf("writing drop-in: %v", err)
			}

			var out bytes.Buffer
			if err := installSystemdUnitsWith(&out, d); err != nil {
				t.Fatalf("installSystemdUnitsWith: %v", err)
			}
			_, err := os.Stat(path)
			if removed := os.IsNotExist(err); removed != tt.wantRemoved {
				t.Errorf("drop-in removed = %v, want %v", removed, tt.wantRemoved)
			}
			if tt.wantRemoved {
				if _, err := os.Stat(dropInDir); !os.IsNotExist(err) {
					t.Errorf("empty drop-in dir was not removed")
				}
			}
		})
	}
}

func TestInstallSystemdUnits_SourceInstall_ResolvesExecStart(t *testing.T) {
	d := testUnitDeps(t)
	binDir := t.TempDir()
	for _, bin := range shadowBinaryNames {
		if err := os.WriteFile(filepath.Join(binDir, bin), []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // test file
			t.Fatalf("writing %s: %v", bin, err)
		}
	}
	d.execPath = func() (string, error) { return filepath.Join(binDir, "ezyshield"), nil }

	var out bytes.Buffer
	if err := installSystemdUnitsWith(&out, d); err != nil {
		t.Fatalf("installSystemdUnitsWith: %v", err)
	}

	for _, unit := range shadowUnitNames {
		path := filepath.Join(d.etcUnitDir, unit)
		data, err := os.ReadFile(path) //nolint:gosec // test path
		if err != nil {
			t.Fatalf("unit %s was not written: %v", unit, err)
		}
		content := string(data)
		if strings.Contains(content, scriptInstallBinDir) {
			t.Errorf("%s still references the hardcoded %s:\n%s", unit, scriptInstallBinDir, content)
		}
		execStart := parseExecStart(content)
		if got := filepath.Dir(execStart); got != binDir {
			t.Errorf("%s ExecStart dir = %q, want %q", unit, got, binDir)
		}
		// The path rewrite must not touch anything else — hardening and the
		// EnvironmentFile directive survive byte-for-byte.
		embedded, err := configs.FS.ReadFile("systemd/" + unit)
		if err != nil {
			t.Fatalf("reading embedded %s: %v", unit, err)
		}
		want := strings.ReplaceAll(string(embedded), scriptInstallBinDir+"/", binDir+"/")
		if content != want {
			t.Errorf("%s content diverges from the embedded unit beyond the path rewrite", unit)
		}
		if !strings.Contains(content, "NoNewPrivileges=yes") {
			t.Errorf("%s lost directive NoNewPrivileges=yes", unit)
		}
	}
	// The daemon unit (the one that loads AI tokens) keeps its
	// EnvironmentFile= directive — the drop-in that used to duplicate it is
	// gone, so losing this line would silently break .env loading.
	daemonUnit, err := os.ReadFile(filepath.Join(d.etcUnitDir, "ezyshield.service")) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("reading daemon unit: %v", err)
	}
	if !strings.Contains(string(daemonUnit), "EnvironmentFile=-/etc/ezyshield/.env") {
		t.Errorf("daemon unit lost its EnvironmentFile= directive")
	}
	if strings.Contains(out.String(), "not found") {
		t.Errorf("unexpected missing-binary warning:\n%s", out.String())
	}
}

func TestInstallSystemdUnits_SourceInstall_FallsBackToLookPath(t *testing.T) {
	d := testUnitDeps(t)
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "ezyshield"), []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // test file
		t.Fatalf("writing binary: %v", err)
	}
	d.lookPath = func(name string) (string, error) {
		if name != "ezyshield" {
			return "", errors.New("not found")
		}
		return filepath.Join(binDir, "ezyshield"), nil
	}

	var out bytes.Buffer
	if err := installSystemdUnitsWith(&out, d); err != nil {
		t.Fatalf("installSystemdUnitsWith: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(d.etcUnitDir, "ezyshield.service")) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("unit was not written: %v", err)
	}
	if got := filepath.Dir(parseExecStart(string(data))); got != binDir {
		t.Errorf("ExecStart dir = %q, want lookPath dir %q", got, binDir)
	}
	// The enforcer binary is absent from binDir — the wizard must say so
	// instead of silently installing a unit that will 203/EXEC.
	if !strings.Contains(out.String(), "ezyshield-enforcer not found") {
		t.Errorf("missing-enforcer warning absent:\n%s", out.String())
	}
}

func TestInstallSystemdUnits_SourceInstall_DefaultsWhenUnresolvable(t *testing.T) {
	d := testUnitDeps(t) // both resolution hooks fail
	var out bytes.Buffer
	if err := installSystemdUnitsWith(&out, d); err != nil {
		t.Fatalf("installSystemdUnitsWith: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(d.etcUnitDir, "ezyshield.service")) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("unit was not written: %v", err)
	}
	if got := filepath.Dir(parseExecStart(string(data))); got != scriptInstallBinDir {
		t.Errorf("ExecStart dir = %q, want script default %q", got, scriptInstallBinDir)
	}
}

func TestResolveUnitBinDir_RejectsRelativePaths(t *testing.T) {
	d := testUnitDeps(t)
	d.execPath = func() (string, error) { return "ezyshield", nil } // degraded os.Executable
	if got := resolveUnitBinDir(d); got != scriptInstallBinDir {
		t.Errorf("resolveUnitBinDir = %q for a relative exec path, want fallback %q", got, scriptInstallBinDir)
	}
}
