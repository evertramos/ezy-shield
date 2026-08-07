package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ── Install shadowing checks (issue #240) ───────────────────────────────────
//
// A host first installed via scripts/get.sh (binaries in /usr/local/bin,
// units in /etc/systemd/system) that later gets `apt install ezyshield` /
// `dnf install ezyshield` can end up silently running the OLD build
// everywhere: /usr/local/bin precedes /usr/bin in PATH, and unit files in
// /etc/systemd/system take precedence over the package's units in
// /usr/lib/systemd/system. dpkg/rpm report the new version installed; the
// binary and service that actually run are the old ones. These checks
// detect that condition and FAIL loudly instead of leaving it silent.

// packageBinDirs are where the .deb/.rpm packages install the ezyshield
// binaries (nfpms `bindir: /usr/bin` in .goreleaser.yaml). /bin is included
// because on many distros it is a symlink to /usr/bin, but some minimal
// images still resolve PATH entries independently.
var packageBinDirs = []string{"/usr/bin", "/bin"}

// packageUnitDir is where the .deb/.rpm packages install systemd units.
const packageUnitDir = "/usr/lib/systemd/system"

// scriptShadowUnitDir is where scripts/get.sh (pre-#240) and manual admins
// following the old docs wrote systemd units. Units here take precedence
// over packageUnitDir at runtime (systemd searches /etc before /usr/lib).
const scriptShadowUnitDir = "/etc/systemd/system"

// shadowBinaryNames are the executables shipped by both the script install
// and the packages.
var shadowBinaryNames = []string{"ezyshield", "ezyshield-enforcer"}

// shadowUnitNames are the systemd unit files shipped by the packages.
var shadowUnitNames = []string{"ezyshield.service", "ezyshield-enforcer.service"}

// checkInstallShadowing runs both shadowing checks below and returns their
// combined results. pathEnv is the PATH-style, ":"-separated list of
// directories to search for shadowing binaries (production callers pass
// os.Getenv("PATH")); it and the unit-dir/bin-dir lists below are all
// injectable so tests never touch the real filesystem.
func checkInstallShadowing(pathEnv string) []CheckResult {
	var out []CheckResult
	out = append(out, checkPathShadowing(pathEnv, shadowBinaryNames)...)
	out = append(out, checkUnitShadowing(scriptShadowUnitDir, packageBinDirs, shadowUnitNames)...)
	return out
}

// checkPathShadowing detects a binary present in more than one directory of
// pathEnv with differing content -- the classic "apt says new, PATH
// resolves old" bug. Content (SHA-256) is compared rather than executing
// the candidates: doctor is a health check, not a place to run arbitrary
// files found on PATH, and hashing is exactly as testable without needing
// real executables. Naming "which one wins" follows PATH's own resolution
// order: the first match in pathEnv is what a plain `ezyshield` invocation
// would run.
func checkPathShadowing(pathEnv string, binaries []string) []CheckResult {
	dirs := filepath.SplitList(pathEnv)
	var out []CheckResult

	for _, bin := range binaries {
		name := "install: " + bin + " PATH shadowing"

		type hit struct {
			path string
			sum  string
		}
		var hits []hit
		seen := map[string]bool{}
		for _, dir := range dirs {
			if dir == "" || seen[dir] {
				continue
			}
			seen[dir] = true
			path := filepath.Join(dir, bin)
			// G703/G304: path is built from PATH directories the admin
			// controls (dirs, ultimately os.Getenv("PATH")), not from
			// log/network input.
			info, err := os.Stat(path) //nolint:gosec
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			sum, err := fileSHA256(path)
			if err != nil {
				continue
			}
			hits = append(hits, hit{path: path, sum: sum})
		}

		if len(hits) < 2 {
			out = append(out, CheckResult{Name: name, Status: statusNA,
				Hint: fmt.Sprintf("found in %d PATH location(s) -- nothing to shadow", len(hits))})
			continue
		}

		differs := false
		for _, h := range hits[1:] {
			if h.sum != hits[0].sum {
				differs = true
				break
			}
		}
		if !differs {
			out = append(out, CheckResult{Name: name, Status: statusPass,
				Hint: fmt.Sprintf("identical content in %d PATH locations", len(hits))})
			continue
		}

		var locs []string
		for _, h := range hits {
			locs = append(locs, h.path)
		}
		out = append(out, CheckResult{
			Name:   name,
			Status: statusFail,
			Hint: fmt.Sprintf(
				"%s present in %d PATH locations with differing content (%s) -- %q wins (first in PATH). "+
					"Cleanup: sudo systemctl stop ezyshield ezyshield-enforcer; sudo rm -f /usr/local/bin/ezyshield /usr/local/bin/ezyshield-enforcer; sudo systemctl daemon-reload",
				bin, len(hits), strings.Join(locs, ", "), hits[0].path),
		})
	}
	return out
}

// checkUnitShadowing detects a systemd unit override in unitDir (production:
// scriptShadowUnitDir, /etc/systemd/system) whose ExecStart points outside
// packageBinDirsArg while a package-owned binary is also present -- meaning
// the *.service an admin sees with `systemctl status` runs the shadow
// build, not the package's. Returns N/A when no package binary is present
// at all (a plain script install has nothing to shadow).
func checkUnitShadowing(unitDir string, packageBinDirsArg, units []string) []CheckResult {
	packageInstalled := false
	for _, d := range packageBinDirsArg {
		for _, bin := range shadowBinaryNames {
			if info, err := os.Stat(filepath.Join(d, bin)); err == nil && info.Mode().IsRegular() {
				packageInstalled = true
			}
		}
	}

	var out []CheckResult
	for _, unit := range units {
		path := filepath.Join(unitDir, unit)
		name := "install: " + unit + " unit shadowing"
		svc := strings.TrimSuffix(unit, ".service")

		if !packageInstalled {
			out = append(out, CheckResult{Name: name, Status: statusNA,
				Hint: "no package-installed binary found -- nothing for a unit override to shadow"})
			continue
		}

		// G304: path is built from a fixed unit dir + a fixed unit name list,
		// not from log/network input.
		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			out = append(out, CheckResult{Name: name, Status: statusNA,
				Hint: fmt.Sprintf("no override at %s", path)})
			continue
		}

		execStart := parseExecStart(string(data))
		if execStart == "" {
			out = append(out, CheckResult{Name: name, Status: statusNA,
				Hint: fmt.Sprintf("%s has no ExecStart= line", path)})
			continue
		}

		if execStartInDirs(execStart, packageBinDirsArg) {
			out = append(out, CheckResult{Name: name, Status: statusPass,
				Hint: fmt.Sprintf("%s ExecStart already points into a package bin dir", path)})
			continue
		}

		out = append(out, CheckResult{
			Name:   name,
			Status: statusFail,
			Hint: fmt.Sprintf(
				"%s overrides the package unit; ExecStart runs outside %s. "+
					"Cleanup: sudo systemctl stop %s; sudo rm -f %s; sudo systemctl daemon-reload; sudo systemctl enable --now %s",
				path, strings.Join(packageBinDirsArg, " or "), svc, path, svc),
		})
	}
	return out
}

// parseExecStart returns the binary path from the first ExecStart= line in
// a systemd unit file, or "" if none is found. This only extracts a field
// for a same-process string comparison (execStartInDirs) -- the value is
// never interpolated into a shell command or exec'd (issue #240 security
// review §1: parsed dpkg/rpm/systemd output is treated as untrusted-ish).
func parseExecStart(unitContent string) string {
	sc := bufio.NewScanner(strings.NewReader(unitContent))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		val := strings.TrimPrefix(line, "ExecStart=")
		// Strip systemd's ExecStart prefix modifiers (-, +, !, !!, :).
		val = strings.TrimLeft(val, "-+!:")
		fields := strings.Fields(val)
		if len(fields) == 0 {
			continue
		}
		return fields[0]
	}
	return ""
}

// execStartInDirs reports whether execStart is exactly "<dir>/ezyshield" or
// "<dir>/ezyshield-enforcer" for one of dirs.
func execStartInDirs(execStart string, dirs []string) bool {
	for _, d := range dirs {
		for _, bin := range shadowBinaryNames {
			if execStart == filepath.Join(d, bin) {
				return true
			}
		}
	}
	return false
}

// fileSHA256 returns the hex-encoded SHA-256 of path's contents.
func fileSHA256(path string) (string, error) {
	// G304: path is built from PATH directories the admin controls, not from
	// log/network input.
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
