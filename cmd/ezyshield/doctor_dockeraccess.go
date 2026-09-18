// SPDX-License-Identifier: AGPL-3.0-only

package main

// doctor_dockeraccess.go — "can the SERVICE USER reach the Docker Engine
// socket?" (issue #580).
//
// The previous check dialed the socket as the invoking user. Doctor is
// normally run with sudo, and an operator's own account is often in the
// 'docker' group, so it printed PASS on hosts where the daemon's ezyshield
// user was denied and the docker collectors were reading nothing at all —
// the same wrong-subject mistake the journald check fixed in issue #455.
//
// The probe here is pure arithmetic and needs no privilege: stat the socket
// for owner/group/mode, resolve the service user's uid and groups from the
// world-readable /etc/passwd and /etc/group, then apply the kernel's own
// permission rule. Nothing is dialed, nothing is executed, no file outside
// those three paths is touched.

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// etcPasswdPath is the user database consulted for the service user's uid and
// primary gid. It is a parameter of the inner functions so tests point at a
// fixture instead of the host's real /etc/passwd.
const etcPasswdPath = "/etc/passwd"

// errStatUnsupported is returned by statSocketOwnership on platforms whose
// FileInfo carries no uid/gid (non-Linux); the check degrades to N/A.
var errStatUnsupported = errors.New("file ownership is not available on this platform")

// socketOwnership is what the kernel compares an accessing process against.
type socketOwnership struct {
	uid      uint32
	gid      uint32
	mode     fs.FileMode
	isSocket bool
}

// serviceUserIDs is the identity systemd starts the unit with: the uid, the
// primary gid, and every supplementary group the user is listed in.
type serviceUserIDs struct {
	uid  uint32
	gids []uint32
}

// dockerSocketAccessInputs collects everything the check reads, so the
// decision logic is testable without touching host state.
type dockerSocketAccessInputs struct {
	socketPath string
	passwdFile string
	groupFile  string
	configPath string
	stat       func(string) (socketOwnership, error)
}

// checkDockerSocketAccess reports whether the service user can read+write the
// Docker Engine socket, for the configurations that actually need it.
func checkDockerSocketAccess(configDir string) CheckResult {
	return dockerSocketAccessCheck(dockerSocketAccessInputs{
		socketPath: defaultDockerSocketPath,
		passwdFile: etcPasswdPath,
		groupFile:  etcGroupPath,
		configPath: filepath.Join(configDir, "config.yaml"),
		stat:       statSocketOwnership,
	})
}

// dockerSocketAccessCheck is the testable core.
//
// N/A when nothing in the configuration talks to the Engine socket, or when
// Docker is absent — neither is a problem to fix. FAIL when a docker
// collector (or the exec watcher) is configured and the service user cannot
// read+write the socket: that host is running a collector that observes
// nothing. PASS when the access exists, whichever path granted it.
func dockerSocketAccessCheck(in dockerSocketAccessInputs) CheckResult {
	const name = "docker: socket access"

	if !configNeedsDockerSocket(in.configPath) {
		return CheckResult{Name: name, Status: statusNA,
			Hint: "no docker collector and no docker_exec watcher configured -- the Engine socket is not needed"}
	}

	own, err := in.stat(in.socketPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return CheckResult{Name: name, Status: statusNA,
			Hint: in.socketPath + " is not present -- Docker is not installed on this host " +
				"(the docker collectors fall back to tailing the container log files)"}
	case errors.Is(err, errStatUnsupported):
		return CheckResult{Name: name, Status: statusNA, Hint: err.Error()}
	case err != nil:
		return CheckResult{Name: name, Status: statusFail,
			Hint: fmt.Sprintf("cannot stat %s: %v -- the path itself is closed to this check "+
				"(a parent directory denies traversal), so the daemon cannot reach it either", in.socketPath, err)}
	case !own.isSocket:
		return CheckResult{Name: name, Status: statusFail,
			Hint: in.socketPath + " exists but is not a unix socket"}
	}

	ids, err := serviceUserIdentity(in.passwdFile, in.groupFile, serviceUser)
	if err != nil {
		return CheckResult{Name: name, Status: statusNA,
			Hint: fmt.Sprintf("cannot evaluate the '%s' service user: %v -- run '%s init' or install the package",
				serviceUser, err, progName)}
	}

	if socketReadWritable(own, ids) {
		return CheckResult{Name: name, Status: statusPass,
			Hint: fmt.Sprintf("service user %s can read and write %s", serviceUser, in.socketPath)}
	}

	return CheckResult{Name: name, Status: statusFail,
		Hint: fmt.Sprintf("service user %s (uid %d) cannot read+write %s (owner %d:%d, mode %04o) -- "+
			"the configured docker collectors observe NOTHING. Access paths, cheapest privilege first: "+
			"(1) collect a host-mounted log file instead of the container's stream (no docker privilege at all); "+
			"(2) expose a read-only, filtered Docker socket proxy to %s; "+
			"(3) add %s to the '%s' group -- that group is root-equivalent on this host (a member can start a "+
			"privileged container), so grant it deliberately and only while docker collectors are configured",
			serviceUser, ids.uid, in.socketPath, own.uid, own.gid, own.mode.Perm(),
			serviceUser, serviceUser, dockerGroupName)}
}

// socketReadWritable applies the kernel's permission rule for read+write
// access: the owner bits when the uid matches, otherwise the group bits when
// any of the user's groups owns the file, otherwise the other bits. The
// classes do NOT fall through — an owner denied by its own bits stays denied.
func socketReadWritable(own socketOwnership, ids serviceUserIDs) bool {
	if ids.uid == 0 {
		return true // root bypasses the mode bits (a service user should not be root)
	}
	perm := own.mode.Perm()
	switch {
	case ids.uid == own.uid:
		return perm&0o600 == 0o600
	case slices.Contains(ids.gids, own.gid):
		return perm&0o060 == 0o060
	default:
		return perm&0o006 == 0o006
	}
}

// serviceUserIdentity resolves user's uid, primary gid and supplementary
// groups from a /etc/passwd- and /etc/group-formatted pair of files. Both are
// host state, parsed as data: every field is compared or converted, never
// interpolated anywhere.
func serviceUserIdentity(passwdFile, groupFile, user string) (serviceUserIDs, error) {
	uid, gid, err := passwdFileIDs(passwdFile, user)
	if err != nil {
		return serviceUserIDs{}, err
	}
	ids := serviceUserIDs{uid: uid, gids: []uint32{gid}}

	// A missing/unreadable group file is not fatal: the primary group alone
	// still answers the common cases, and a check that refuses to run is
	// worse than one that evaluates slightly less.
	extra, err := groupFileGIDs(groupFile, user)
	if err == nil {
		for _, g := range extra {
			if !slices.Contains(ids.gids, g) {
				ids.gids = append(ids.gids, g)
			}
		}
	}
	return ids, nil
}

// passwdFileIDs returns user's uid and primary gid from a /etc/passwd-format
// file. Users defined only in a directory service (LDAP/SSSD) are not found
// here; the caller degrades to N/A rather than guessing.
func passwdFileIDs(passwdFile, user string) (uid, gid uint32, err error) {
	f, err := os.Open(passwdFile) //nolint:gosec // fixed path (or a test fixture); read-only
	if err != nil {
		return 0, 0, err
	}
	defer f.Close() //nolint:errcheck // read-only close

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 || fields[0] != user {
			continue
		}
		u, uerr := strconv.ParseUint(fields[2], 10, 32)
		g, gerr := strconv.ParseUint(fields[3], 10, 32)
		if uerr != nil || gerr != nil {
			return 0, 0, fmt.Errorf("user %q has an unparsable uid/gid in %s", user, passwdFile)
		}
		return uint32(u), uint32(g), nil
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}
	return 0, 0, fmt.Errorf("user %q not found in %s", user, passwdFile)
}

// groupFileGIDs returns the gids of every group that lists user among its
// members (field 4 — the list `usermod -aG` writes).
func groupFileGIDs(groupFile, user string) ([]uint32, error) {
	f, err := os.Open(groupFile) //nolint:gosec // fixed path (or a test fixture); read-only
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only close

	var gids []uint32
	sc := bufio.NewScanner(f)
	// A pathological member list must not trip the default 64 KiB token cap.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		gid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		for _, m := range strings.Split(fields[3], ",") {
			if strings.TrimSpace(m) == user {
				gids = append(gids, uint32(gid))
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return gids, nil
}
