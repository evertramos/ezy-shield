// SPDX-License-Identifier: AGPL-3.0-only

// Package unitcheck holds the systemd unit-hardening checks from issue
// #213, implemented once and consumed by BOTH `ezyshield doctor`
// (on-demand) and the daemon's periodic hardening self-check (issue #563).
//
// Two unit settings are load-bearing for enforcement: the enforcer needs
// AF_NETLINK inside RestrictAddressFamilies (nftables speaks netlink), and
// each service needs its RuntimeDirectory (socket dir). A hand-installed,
// locally modified, or drop-in-overridden unit that loses either produces
// exactly the silent-non-enforcement failure mode this project treats as
// worst case: bans recorded, nothing applied.
//
// The checks read the EFFECTIVE configuration via `systemctl show`
// (fragment + drop-in aware), so a stripped drop-in is caught even when
// the shipped unit file on disk looks fine. Everything here is READ-ONLY —
// no unit is ever edited, no service restarted. The functional NetlinkProbe
// complements the text checks: the enforcer helper's read-only "netcheck"
// verb runs one `nft list set` inside its own sandbox, testing effect
// rather than configuration text.
package unitcheck

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

// Status classifies one check outcome.
type Status string

// Check outcomes. NA covers hosts without systemd, units not installed,
// and helpers predating the netcheck verb — all healthy for monitoring
// purposes (script/manual installs must stay quiet).
const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusWarn Status = "warn"
	StatusNA   Status = "na"
)

// Result is one check outcome.
type Result struct {
	Name   string
	Status Status
	Hint   string
}

// unitProps is the parsed key=value output of `systemctl show` for one unit.
type unitProps map[string]string

// ShowUnitProps returns the effective properties of unit, or ok=false when
// this host has no systemd (non-systemd hosts skip these checks). It is a
// variable so tests inject fixture outputs without a systemd dependency.
var ShowUnitProps = func(ctx context.Context, unit string) (props map[string]string, ok bool, err error) {
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

// Unit names the checks cover.
const (
	EnforcerUnitName = "ezyshield-enforcer.service"
	DaemonUnitName   = "ezyshield.service"
)

// dropInHint renders the exact fix: a drop-in snippet restoring setting for
// unit. Never applied by us (read-only by contract).
func dropInHint(unit, section, setting string) string {
	return fmt.Sprintf(
		"restore it with a drop-in: systemctl edit %s  and add:  [%s]\\n%s  then: systemctl daemon-reload && systemctl restart %s",
		unit, section, setting, unit)
}

// UnitHardening verifies the effective unit configuration on systemd
// hosts: AF_NETLINK reachable for the enforcer, RuntimeDirectory present
// for both services. Non-systemd hosts get a single N/A.
func UnitHardening(ctx context.Context) []Result {
	type unitCheck struct {
		unit string
		fn   func(unitProps) Result
	}
	checks := []unitCheck{
		{EnforcerUnitName, checkEnforcerNetlinkAllowed},
		{EnforcerUnitName, func(p unitProps) Result {
			return checkRuntimeDirectory(EnforcerUnitName, "ezyshield-enforcer", p)
		}},
		{DaemonUnitName, func(p unitProps) Result {
			return checkRuntimeDirectory(DaemonUnitName, "ezyshield", p)
		}},
	}

	var out []Result
	shown := map[string]unitProps{}
	for _, c := range checks {
		props, has := shown[c.unit]
		if !has {
			rawProps, systemd, err := ShowUnitProps(ctx, c.unit)
			props = unitProps(rawProps)
			if !systemd {
				return []Result{{Name: "systemd units: hardening", Status: StatusNA,
					Hint: "no systemctl on this host -- unit hardening checks apply to systemd installs only"}}
			}
			if err != nil {
				out = append(out, Result{Name: c.unit + ": hardening", Status: StatusWarn,
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
			out = append(out, Result{Name: c.unit + ": hardening", Status: StatusNA,
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
func checkEnforcerNetlinkAllowed(props unitProps) Result {
	const name = EnforcerUnitName + ": AF_NETLINK allowed"
	raf := strings.TrimSpace(props["RestrictAddressFamilies"])
	fix := dropInHint(EnforcerUnitName, "Service", "RestrictAddressFamilies=AF_UNIX AF_NETLINK")
	switch {
	case raf == "":
		return Result{Name: name, Status: StatusPass,
			Hint: "no address-family restriction in effect"}
	case strings.HasPrefix(raf, "~"):
		if hasField(strings.TrimPrefix(raf, "~"), "AF_NETLINK") {
			return Result{Name: name, Status: StatusFail,
				Hint: "RestrictAddressFamilies DENIES AF_NETLINK -- the enforcer cannot program nftables: bans get recorded but never applied; " + fix}
		}
		return Result{Name: name, Status: StatusPass}
	case hasField(raf, "AF_NETLINK"):
		return Result{Name: name, Status: StatusPass}
	default:
		return Result{Name: name, Status: StatusFail,
			Hint: "effective RestrictAddressFamilies (" + raf + ") lacks AF_NETLINK -- the enforcer cannot program nftables: bans get recorded but never applied; " + fix}
	}
}

// checkRuntimeDirectory asserts the effective RuntimeDirectory still
// provides dir (the unit's socket directory under /run).
func checkRuntimeDirectory(unit, dir string, props unitProps) Result {
	name := unit + ": runtime directory"
	if hasField(props["RuntimeDirectory"], dir) {
		return Result{Name: name, Status: StatusPass}
	}
	return Result{Name: name, Status: StatusFail,
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

// NetlinkProbe performs the functional half of issue #213: ask the running
// helper to execute a read-only nft operation inside its own sandbox
// ("netcheck" verb). This tests effect — capability + address-family +
// seccomp all at once — where the text checks only test configuration.
// N/A when the helper socket is down (socket connectivity is its own
// doctor check) or when the helper predates the verb.
func NetlinkProbe(ctx context.Context, socketPath string) Result {
	const name = "enforcer: netlink probe"
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(probeCtx, "unix", socketPath)
	if err != nil {
		return Result{Name: name, Status: StatusNA,
			Hint: "enforcer socket unreachable -- see the socket connectivity check"}
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := json.NewEncoder(conn).Encode(enforce.Request{Verb: "netcheck"}); err != nil {
		return Result{Name: name, Status: StatusNA, Hint: "send netcheck: " + err.Error()}
	}
	var resp enforce.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Result{Name: name, Status: StatusNA, Hint: "read netcheck response: " + err.Error()}
	}
	switch {
	case resp.OK:
		return Result{Name: name, Status: StatusPass,
			Hint: "helper executed a read-only nft operation inside its sandbox"}
	case strings.Contains(resp.Error, "unknown verb"):
		return Result{Name: name, Status: StatusNA,
			Hint: "running helper predates the netcheck verb -- update ezyshield-enforcer to enable the functional probe"}
	default:
		return Result{Name: name, Status: StatusFail,
			Hint: "helper cannot reach netlink from inside its sandbox: " + resp.Error +
				" -- check RestrictAddressFamilies/AmbientCapabilities in the effective unit (systemctl show " + EnforcerUnitName + ")"}
	}
}

// Failures filters results down to hard failures — the transition signal
// the daemon's self-check monitors (NA and WARN count as healthy).
func Failures(results []Result) []Result {
	var out []Result
	for _, r := range results {
		if r.Status == StatusFail {
			out = append(out, r)
		}
	}
	return out
}
