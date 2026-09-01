// SPDX-License-Identifier: AGPL-3.0-only

package main

// Doctor check for the service user's membership in the 'docker' group
// (issue #574). Membership is not a read permission: the group owns the
// Docker Engine socket, and any process that can reach it can start a
// privileged container — i.e. become root on the host. The log-parsing
// daemon is exactly the process that must not have that path, so doctor
// reports the membership wherever it exists, including hosts provisioned
// before the grant became an explicit opt-in (a package upgrade never
// revokes a group).

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/evertramos/ezy-shield/internal/config"
)

const (
	// etcGroupPath is the group database consulted by the docker-group
	// check. It is a parameter of the inner function so tests can point at
	// a fixture instead of the host's real /etc/group.
	etcGroupPath = "/etc/group"
	// serviceUser is the account the daemon runs as (User= in the unit).
	serviceUser = "ezyshield"
	// dockerGroupName is the group that owns the Docker Engine socket.
	dockerGroupName = "docker"
)

// checkServiceUserDockerGroup reports whether the ezyshield service user is a
// member of the root-equivalent 'docker' group, and whether anything in the
// configuration actually needs that access.
func checkServiceUserDockerGroup(configDir string) CheckResult {
	return serviceUserDockerGroupCheck(etcGroupPath, filepath.Join(configDir, "config.yaml"))
}

// serviceUserDockerGroupCheck is the testable core: groupFile is a
// /etc/group-formatted database, configPath the config.yaml whose collectors
// decide which remediation hint applies.
//
// PASS/N/A when the grant does not exist (no docker group on the host, or the
// service user is not in it) — there is nothing to report. WARN when it does,
// because the membership is a real privilege the operator should have chosen
// deliberately; the hint differs by whether the configuration justifies it.
func serviceUserDockerGroupCheck(groupFile, configPath string) CheckResult {
	const name = "service user: docker group"

	exists, member, err := groupFileMembership(groupFile, dockerGroupName, serviceUser)
	switch {
	case err != nil:
		return CheckResult{Name: name, Status: statusNA,
			Hint: fmt.Sprintf("cannot read %s: %v", groupFile, err)}
	case !exists:
		return CheckResult{Name: name, Status: statusNA,
			Hint: "no '" + dockerGroupName + "' group on this host -- Docker not installed"}
	case !member:
		return CheckResult{Name: name, Status: statusPass,
			Hint: serviceUser + " is not in the '" + dockerGroupName + "' group"}
	}

	warn := "service user " + serviceUser + " is in the '" + dockerGroupName +
		"' group -- root-equivalent on this host (that group is the Docker Engine API, " +
		"so any process running as " + serviceUser + " can start a privileged container)"
	if configNeedsDockerSocket(configPath) {
		return CheckResult{Name: name, Status: statusWarn,
			Hint: warn + "; required by the configured docker collectors; accepted risk -- see security docs"}
	}
	return CheckResult{Name: name, Status: statusWarn,
		Hint: warn + "; no docker collector is configured; revoke with: gpasswd -d " +
			serviceUser + " " + dockerGroupName + " && systemctl restart ezyshield"}
}

// configNeedsDockerSocket reports whether the configuration declares anything
// that talks to the Docker Engine socket: a docker log collector or the
// docker exec watcher. An unreadable or unloadable config answers false —
// the config.yaml checks already report that, and the more urgent hint (a
// privilege nothing justifies) is the safer thing to print when in doubt.
func configNeedsDockerSocket(configPath string) bool {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return false
	}
	for _, c := range cfg.Collectors {
		if c.Kind == "docker" {
			return true
		}
	}
	return cfg.DockerExec != nil && cfg.DockerExec.Enabled
}

// groupFileMembership parses a /etc/group-formatted file and reports whether
// the group exists and whether user is listed among its members.
//
// It reads the supplementary member list only (field 4) — the same list
// `usermod -aG` writes — which is where a service account's docker membership
// always lands. A user whose PRIMARY group were 'docker' would not appear
// there; that is not a shape any EzyShield install produces (the service user
// is created with its own group), and reading /etc/passwd to cover it would
// widen this check for no real case.
//
// The file is host state, not attacker input, and is treated as data
// regardless: every field is compared, never interpolated anywhere.
func groupFileMembership(groupFile, group, user string) (exists, member bool, err error) {
	f, err := os.Open(groupFile) //nolint:gosec // fixed path (or a test fixture); read-only
	if err != nil {
		return false, false, err
	}
	defer f.Close() //nolint:errcheck // read-only close

	sc := bufio.NewScanner(f)
	// A pathological /etc/group line (very long member list) must not make
	// the check fail on the default 64 KiB token limit.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 || fields[0] != group {
			continue
		}
		exists = true
		if len(fields) < 4 {
			return exists, false, nil
		}
		for _, m := range strings.Split(fields[3], ",") {
			if strings.TrimSpace(m) == user {
				return exists, true, nil
			}
		}
		return exists, false, nil
	}
	if err := sc.Err(); err != nil {
		return false, false, err
	}
	return false, false, nil
}
