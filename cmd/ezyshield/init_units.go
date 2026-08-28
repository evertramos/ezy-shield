// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/evertramos/ezy-shield/configs"
)

// ── systemd unit installation (issue #449) ──────────────────────────────────
//
// The embedded units in configs/systemd/ carry the script-install ExecStart
// path (/usr/local/bin). The .deb/.rpm packages ship their own units in
// /usr/lib/systemd/system (path rewritten to /usr/bin by
// scripts/package/mk-package-units.sh). /etc/systemd/system takes precedence
// over /usr/lib/systemd/system, so if the wizard copies its embedded units
// there on a package install, the packaged units are shadowed by units whose
// ExecStart points at a binary that does not exist — both services crash-loop
// with status=203/EXEC while `systemctl is-enabled` still reports enabled
// (issue #449, the exact condition `ezyshield doctor` flags via
// checkUnitShadowing since issue #240).
//
// The rules, in order:
//  1. Packaged units present  → write NOTHING to /etc/systemd/system (it is
//     the administrator's namespace, not ours); remove only the broken
//     leftovers earlier wizard versions wrote there.
//  2. No packaged units (source / go-install / script flow) → install the
//     embedded units with ExecStart resolved from the running binary's real
//     location, never a hardcoded path.
// The env.conf drop-in older wizards wrote is redundant either way — every
// current unit source already carries EnvironmentFile= — so a byte-exact
// leftover is removed too.

// scriptInstallBinDir is the bin dir the embedded units reference and the
// default when the running binary's location cannot be resolved. It matches
// scripts/get.sh's INSTALL_DIR.
const scriptInstallBinDir = "/usr/local/bin"

// unitInstallDeps carries the filesystem locations and process-introspection
// hooks used by installSystemdUnitsWith, injectable so tests never touch
// /etc or /usr/lib.
type unitInstallDeps struct {
	etcUnitDir string                       // production: defaultSystemdDir
	pkgUnitDir string                       // production: packageUnitDir (doctor_shadow.go)
	execPath   func() (string, error)       // production: os.Executable
	lookPath   func(string) (string, error) // production: exec.LookPath
}

func defaultUnitInstallDeps() unitInstallDeps {
	return unitInstallDeps{
		etcUnitDir: defaultSystemdDir,
		pkgUnitDir: packageUnitDir,
		execPath:   os.Executable,
		lookPath:   exec.LookPath,
	}
}

func installSystemdUnits(out io.Writer) error {
	return installSystemdUnitsWith(out, defaultUnitInstallDeps())
}

func installSystemdUnitsWith(out io.Writer, d unitInstallDeps) error {
	if packagedUnitsPresent(d.pkgUnitDir) {
		fmt.Fprintf(out, "  using packaged systemd units from %s — nothing written to %s\n", //nolint:errcheck // best-effort console output
			d.pkgUnitDir, d.etcUnitDir)
		if err := removeBrokenUnitOverrides(out, d); err != nil {
			return err
		}
		removeOwnEnvDropIn(out, d.etcUnitDir)
		return nil
	}

	binDir := resolveUnitBinDir(d)
	for _, unit := range shadowUnitNames {
		data, err := configs.FS.ReadFile("systemd/" + unit)
		if err != nil {
			return fmt.Errorf("reading embedded %s: %w", unit, err)
		}
		content := strings.ReplaceAll(string(data), scriptInstallBinDir+"/", binDir+"/")
		dst := filepath.Join(d.etcUnitDir, unit)
		if err := os.WriteFile(dst, []byte(content), 0o644); err != nil { //nolint:gosec // 0644 is standard for systemd units
			return fmt.Errorf("installing %s: %w", dst, err)
		}
		if _, err := fmt.Fprintf(out, "  installed %s (binaries in %s)\n", dst, binDir); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	for _, bin := range shadowBinaryNames {
		path := filepath.Join(binDir, bin)
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			fmt.Fprintf(out, "  ⚠  %s not found — the matching service will fail to start until it exists there\n", path) //nolint:errcheck // best-effort console output
		}
	}
	removeOwnEnvDropIn(out, d.etcUnitDir)
	return nil
}

// packagedUnitsPresent reports whether the OS package's unit files exist in
// pkgUnitDir (/usr/lib/systemd/system). Any one of them counts: a partial
// package layout still means a package manager owns unit installation on
// this host and the wizard must stay out of /etc/systemd/system.
func packagedUnitsPresent(pkgUnitDir string) bool {
	for _, unit := range shadowUnitNames {
		if info, err := os.Stat(filepath.Join(pkgUnitDir, unit)); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// resolveUnitBinDir returns the directory the generated units' ExecStart
// should reference: the running binary's real directory (symlinks resolved),
// falling back to PATH lookup, then to the script-install default. The
// result is always an absolute path — relative answers (e.g. `./ezyshield`
// when os.Executable degrades) would produce a unit systemd rejects.
func resolveUnitBinDir(d unitInstallDeps) string {
	for _, resolve := range []func() (string, error){
		d.execPath,
		func() (string, error) { return d.lookPath("ezyshield") },
	} {
		p, err := resolve()
		if err != nil || p == "" {
			continue
		}
		if real, rerr := filepath.EvalSymlinks(p); rerr == nil {
			p = real
		}
		if filepath.IsAbs(p) {
			return filepath.Dir(p)
		}
	}
	return scriptInstallBinDir
}

// removeBrokenUnitOverrides deletes unit files in etcUnitDir (the exact
// fixed names in shadowUnitNames, never a glob — this runs as root) whose
// ExecStart binary does not exist: the crash-loop state older wizard
// versions created on package installs (issue #449). An override whose
// ExecStart target DOES exist is a deliberate admin override of a unit that
// can run — it is left in place with a warning (`ezyshield doctor` reports
// the shadowing, issue #240).
func removeBrokenUnitOverrides(out io.Writer, d unitInstallDeps) error {
	for _, unit := range shadowUnitNames {
		path := filepath.Join(d.etcUnitDir, unit)
		// G304: fixed unit dir + fixed unit name list, no external input.
		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			continue // no override present
		}
		execStart := parseExecStart(string(data))
		if execStart == "" {
			fmt.Fprintf(out, "  ⚠  %s has no ExecStart= line — left untouched\n", path) //nolint:errcheck // best-effort console output
			continue
		}
		// G703: execStart comes from a root-owned unit file in
		// /etc/systemd/system (admin namespace, not log/network input) and is
		// only stat'd for existence — never opened, executed, or written.
		if _, err := os.Stat(execStart); err == nil { //nolint:gosec
			fmt.Fprintf(out, "  ⚠  %s overrides the packaged unit (ExecStart=%s exists) — left in place; `ezyshield doctor` reports unit shadowing\n", //nolint:errcheck // best-effort console output
				path, execStart)
			continue
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("removing stale unit override %s: %w", path, err)
		}
		fmt.Fprintf(out, "  removed stale unit override %s (ExecStart pointed at missing %s)\n", path, execStart) //nolint:errcheck // best-effort console output
	}
	return nil
}

// envDropInContent is the exact drop-in older wizard versions wrote to
// <etcUnitDir>/ezyshield.service.d/env.conf. Every current unit source
// (embedded and packaged) already carries this EnvironmentFile= line, so the
// drop-in is pure duplication.
func envDropInContent() string {
	return "[Service]\nEnvironmentFile=-" + defaultConfigDir + "/" + envFileName + "\n"
}

// removeOwnEnvDropIn removes the redundant env.conf drop-in ONLY when its
// content is byte-identical to what this wizard historically wrote — an
// edited drop-in is the administrator's and stays. Best-effort: the drop-in
// is harmless (it restates a directive the active unit already has), so
// removal failures only warn. The containing directory is removed only if
// empty.
func removeOwnEnvDropIn(out io.Writer, etcUnitDir string) {
	dropInDir := filepath.Join(etcUnitDir, "ezyshield.service.d")
	path := filepath.Join(dropInDir, "env.conf")
	// G304: fixed path under the systemd unit dir, no external input.
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil || string(data) != envDropInContent() {
		return
	}
	if err := os.Remove(path); err != nil {
		fmt.Fprintf(out, "  ⚠  could not remove redundant drop-in %s: %v\n", path, err) //nolint:errcheck // best-effort console output
		return
	}
	_ = os.Remove(dropInDir)                                                                            // only succeeds when empty — anything else in there is the admin's
	fmt.Fprintf(out, "  removed redundant drop-in %s (EnvironmentFile= is in the unit itself)\n", path) //nolint:errcheck // best-effort console output
}
