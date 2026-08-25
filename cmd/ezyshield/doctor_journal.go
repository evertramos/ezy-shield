package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
)

// ── journald readability, evaluated as the service user (issue #455) ────────
//
// The journald collector runs `journalctl` as the daemon's `User=ezyshield`,
// and the journal is group-readable only (root:systemd-journal). Probing as
// the *invoking* user — root, since doctor is normally run with sudo —
// validated the wrong subject: it printed PASS on a host where the daemon
// was failing continuously with "No journal files were opened due to
// insufficient permissions" (issue #454, the exact condition this check
// exists to catch). When doctor runs as root and the service user exists,
// the probe now drops to that user's full credentials (uid, gid,
// supplementary groups — resolved at process start, exactly like systemd
// does for the unit).

// journaldServiceUser is the account the daemon unit runs under
// (configs/systemd/ezyshield.service `User=`; created by the package
// postinstall or by `ezyshield init`).
const journaldServiceUser = "ezyshield"

// journalProbeID is the identity the journal probe evaluates. A nil ids
// slice means "run as the current process user" (no privilege drop).
type journalProbeID struct {
	label  string   // whose access is being evaluated, shown in the check name
	uid    uint32   // valid only when drop is true
	gid    uint32   // valid only when drop is true
	groups []uint32 // supplementary groups, valid only when drop is true
	drop   bool     // true: probe with the credentials above
	note   string   // hint context when identity resolution degraded
}

// journalProbeIdentity resolves which identity to probe as. All host
// introspection is injected so tests never depend on real users:
// euid is os.Geteuid(); current is user.Current; lookup is user.Lookup;
// groupIDs wraps (*user.User).GroupIds.
func journalProbeIdentity(
	euid int,
	current func() (*user.User, error),
	lookup func(string) (*user.User, error),
	groupIDs func(*user.User) ([]string, error),
) journalProbeID {
	if euid != 0 {
		// Unprivileged doctor cannot setuid; evaluate the invoker but say so.
		label := "current user"
		if cu, err := current(); err == nil && cu.Username != "" {
			label = cu.Username
		}
		return journalProbeID{
			label: label,
			note:  "run doctor with sudo to evaluate the '" + journaldServiceUser + "' service user the daemon runs as",
		}
	}

	su, err := lookup(journaldServiceUser)
	if err != nil {
		return journalProbeID{
			label: "root",
			note: "'" + journaldServiceUser + "' user not found (run '" + progName + " init' or install the package) -- " +
				"probing as root, which can read journals the daemon cannot",
		}
	}

	uid, uerr := strconv.ParseUint(su.Uid, 10, 32)
	gid, gerr := strconv.ParseUint(su.Gid, 10, 32)
	if uerr != nil || gerr != nil {
		return journalProbeID{
			label: "root",
			note:  "could not parse the '" + journaldServiceUser + "' uid/gid -- probing as root",
		}
	}

	id := journalProbeID{label: journaldServiceUser, uid: uint32(uid), gid: uint32(gid), drop: true}
	// Supplementary groups are what actually grant journal access
	// (systemd-journal); resolve them like systemd resolves the unit's at
	// process start. A lookup failure degrades to uid/gid only — the probe
	// then reports the same denial the daemon would hit.
	if ids, err := groupIDs(su); err == nil {
		for _, g := range ids {
			n, err := strconv.ParseUint(g, 10, 32)
			if err != nil {
				continue
			}
			id.groups = append(id.groups, uint32(n))
		}
	}
	return id
}

// checkJournaldReadable returns PASS when journalctl is present and the
// identity the daemon runs under can actually read the journal.
func checkJournaldReadable() CheckResult {
	id := journalProbeIdentity(os.Geteuid(), user.Current, user.Lookup,
		func(u *user.User) ([]string, error) { return u.GroupIds() })
	return probeJournalReadable(id, "")
}

// probeJournalReadable runs the journalctl probe as id and converts the
// outcome into a CheckResult. jctlBin overrides the probed binary for tests;
// empty means "resolve journalctl from PATH" (same override pattern as
// collector.JournaldCollector.Cmd).
func probeJournalReadable(id journalProbeID, jctlBin string) CheckResult {
	name := "journald: readable (as " + id.label + ")"

	jctlPath := jctlBin
	if jctlPath == "" {
		p, err := exec.LookPath("journalctl")
		if err != nil {
			return CheckResult{
				Name:   name,
				Status: statusFail,
				Hint:   "journalctl not found -- EzyShield requires systemd journald to read SSH/service logs",
			}
		}
		jctlPath = p
	}

	// Quick probe: list 0 lines; non-zero exit means access is denied.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// G204: jctlPath is from LookPath("journalctl"), fixed args, no user input.
	cmd := exec.CommandContext(ctx, jctlPath, "-n", "0", "--no-pager") //nolint:gosec
	applyProbeCredential(cmd, id)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return CheckResult{
			Name:   name,
			Status: statusFail,
			Hint: fmt.Sprintf(
				"journalctl failed as %s: %v (%s) -- fix: usermod -aG systemd-journal %s, then restart the service "+
					"(the packaged unit also sets SupplementaryGroups=systemd-journal)",
				id.label, err, strings.TrimSpace(string(out)), journaldServiceUser),
		}
	}

	res := CheckResult{Name: name, Status: statusPass}
	res.Hint = id.note // context for degraded identities; empty otherwise
	return res
}
