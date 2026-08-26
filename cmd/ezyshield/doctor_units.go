// SPDX-License-Identifier: AGPL-3.0-only

package main

// ── Systemd unit hardening checks (issue #213) ──────────────────────────────
//
// Two unit settings are load-bearing for enforcement: the enforcer needs
// AF_NETLINK inside RestrictAddressFamilies (nftables speaks netlink), and
// each service needs its RuntimeDirectory (socket dir). The shipped units
// carry both — but a hand-installed, locally modified, or drop-in-overridden
// unit that loses either produces exactly the silent-non-enforcement failure
// mode this project treats as worst case: bans recorded, nothing applied.
//
// The checks read the EFFECTIVE configuration via `systemctl show` (which is
// fragment + drop-in aware), so a stripped drop-in is caught even when the
// shipped unit file on disk looks fine. Everything here is read-only —
// doctor never edits units. A functional probe complements the text checks:
// the enforcer helper's read-only "netcheck" verb runs one `nft list set`
// inside its own sandbox, testing effect rather than configuration text.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/internal/enforce"
)

// unitProps is the parsed key=value output of `systemctl show` for one unit.
type unitProps map[string]string

// showUnitProps returns the effective properties of unit, or ok=false when
// this host has no systemd (non-systemd hosts skip these checks). It is a
// variable so tests inject fixture outputs without a systemd dependency.
var showUnitProps = func(ctx context.Context, unit string) (props unitProps, ok bool, err error) {
	if _, lerr := exec.LookPath("systemctl"); lerr != nil {
		return nil, false, nil
	}
	// G204: fixed binary, fixed property list, unit names are compile-time
	// constants below — nothing user- or log-controlled.
	out, err := exec.CommandContext(ctx, "systemctl", "show", unit, //nolint:gosec
		"--property=LoadState,RestrictAddressFamilies,RuntimeDirectory", "--no-pager").Output()
	if err != nil {
		return nil, true, err
	}
	return parseUnitProps(string(out)), true, nil
}

// parseUnitProps parses `systemctl show` key=value lines.
func parseUnitProps(out string) unitProps {
	props := unitProps{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, found := strings.Cut(strings.TrimSpace(line), "="); found {
			props[k] = v
		}
	}
	return props
}

const (
	enforcerUnitName = "ezyshield-enforcer.service"
	daemonUnitName   = "ezyshield.service"
)

// dropInHint renders the exact fix: a drop-in snippet restoring setting for
// unit. Doctor never applies it (read-only by contract).
func dropInHint(unit, section, setting string) string {
	return fmt.Sprintf(
		"restore it with a drop-in: systemctl edit %s  and add:  [%s]\\n%s  then: systemctl daemon-reload && systemctl restart %s",
		unit, section, setting, unit)
}

// checkUnitHardening verifies the effective unit configuration on systemd
// hosts: AF_NETLINK reachable for the enforcer, RuntimeDirectory present for
// both services. Non-systemd hosts get a single N/A.
func checkUnitHardening(ctx context.Context) []CheckResult {
	type unitCheck struct {
		unit string
		fn   func(unitProps) CheckResult
	}
	checks := []unitCheck{
		{enforcerUnitName, checkEnforcerNetlinkAllowed},
		{enforcerUnitName, func(p unitProps) CheckResult {
			return checkRuntimeDirectory(enforcerUnitName, "ezyshield-enforcer", p)
		}},
		{daemonUnitName, func(p unitProps) CheckResult {
			return checkRuntimeDirectory(daemonUnitName, "ezyshield", p)
		}},
	}

	var out []CheckResult
	shown := map[string]unitProps{}
	for _, c := range checks {
		props, has := shown[c.unit]
		if !has {
			var systemd bool
			var err error
			props, systemd, err = showUnitProps(ctx, c.unit)
			if !systemd {
				return []CheckResult{{Name: "systemd units: hardening", Status: statusNA,
					Hint: "no systemctl on this host -- unit hardening checks apply to systemd installs only"}}
			}
			if err != nil {
				out = append(out, CheckResult{Name: c.unit + ": hardening", Status: statusWarn,
					Hint: "systemctl show failed: " + err.Error()})
				shown[c.unit] = nil
				continue
			}
			shown[c.unit] = props
		}
		if props == nil {
			continue // show failed above; already reported once
		}
		if props["LoadState"] != "loaded" {
			out = append(out, CheckResult{Name: c.unit + ": hardening", Status: statusNA,
				Hint: "unit not installed (LoadState=" + props["LoadState"] + ") -- script/manual runs skip this check"})
			shown[c.unit] = nil
			continue
		}
		out = append(out, c.fn(props))
	}
	return out
}

// checkEnforcerNetlinkAllowed asserts the effective RestrictAddressFamilies
// still lets the enforcer open netlink sockets. An empty value means the
// unit applies no restriction (permitted); a "~"-prefixed value is a
// deny-list; anything else is an allow-list that must name AF_NETLINK.
func checkEnforcerNetlinkAllowed(props unitProps) CheckResult {
	const name = enforcerUnitName + ": AF_NETLINK allowed"
	raf := strings.TrimSpace(props["RestrictAddressFamilies"])
	fix := dropInHint(enforcerUnitName, "Service", "RestrictAddressFamilies=AF_UNIX AF_NETLINK")
	switch {
	case raf == "":
		return CheckResult{Name: name, Status: statusPass,
			Hint: "no address-family restriction in effect"}
	case strings.HasPrefix(raf, "~"):
		if hasField(strings.TrimPrefix(raf, "~"), "AF_NETLINK") {
			return CheckResult{Name: name, Status: statusFail,
				Hint: "RestrictAddressFamilies DENIES AF_NETLINK -- the enforcer cannot program nftables: bans get recorded but never applied; " + fix}
		}
		return CheckResult{Name: name, Status: statusPass}
	case hasField(raf, "AF_NETLINK"):
		return CheckResult{Name: name, Status: statusPass}
	default:
		return CheckResult{Name: name, Status: statusFail,
			Hint: "effective RestrictAddressFamilies (" + raf + ") lacks AF_NETLINK -- the enforcer cannot program nftables: bans get recorded but never applied; " + fix}
	}
}

// checkRuntimeDirectory asserts the effective RuntimeDirectory still
// provides dir (the unit's socket directory under /run).
func checkRuntimeDirectory(unit, dir string, props unitProps) CheckResult {
	name := unit + ": runtime directory"
	if hasField(props["RuntimeDirectory"], dir) {
		return CheckResult{Name: name, Status: statusPass}
	}
	return CheckResult{Name: name, Status: statusFail,
		Hint: fmt.Sprintf("effective RuntimeDirectory (%q) does not provide %q -- /run/%s is never created and the unit's socket cannot exist; %s",
			props["RuntimeDirectory"], dir, dir, dropInHint(unit, "Service", "RuntimeDirectory="+dir))}
}

// hasField reports whether list (whitespace-separated) contains exactly want.
func hasField(list, want string) bool {
	for _, f := range strings.Fields(list) {
		if f == want {
			return true
		}
	}
	return false
}

// checkEnforcerNetlinkProbe performs the functional half of issue #213: ask
// the running helper to execute a read-only nft operation inside its own
// sandbox ("netcheck" verb). This tests effect — capability + address-family
// + seccomp all at once — where the text checks only test configuration.
// N/A when the helper socket is down (socket connectivity is its own check)
// or when the helper predates the verb.
func checkEnforcerNetlinkProbe(path string) CheckResult {
	const name = "enforcer: netlink probe"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return CheckResult{Name: name, Status: statusNA,
			Hint: "enforcer socket unreachable -- see the socket connectivity check"}
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := json.NewEncoder(conn).Encode(enforce.Request{Verb: "netcheck"}); err != nil {
		return CheckResult{Name: name, Status: statusNA, Hint: "send netcheck: " + err.Error()}
	}
	var resp enforce.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return CheckResult{Name: name, Status: statusNA, Hint: "read netcheck response: " + err.Error()}
	}
	switch {
	case resp.OK:
		return CheckResult{Name: name, Status: statusPass,
			Hint: "helper executed a read-only nft operation inside its sandbox"}
	case strings.Contains(resp.Error, "unknown verb"):
		return CheckResult{Name: name, Status: statusNA,
			Hint: "running helper predates the netcheck verb -- update ezyshield-enforcer to enable the functional probe"}
	default:
		return CheckResult{Name: name, Status: statusFail,
			Hint: "helper cannot reach netlink from inside its sandbox: " + resp.Error +
				" -- check RestrictAddressFamilies/AmbientCapabilities in the effective unit (systemctl show " + enforcerUnitName + ")"}
	}
}
