package main

// Tests for the systemd unit hardening checks (issue #213), driven by
// fixture `systemctl show` outputs injected through showUnitProps — no
// systemd needed on the test host.

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/enforce"
)

// hardenedShow mirrors the shipped units' effective properties.
var hardenedShow = map[string]string{
	enforcerUnitName: "LoadState=loaded\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\nRuntimeDirectory=ezyshield-enforcer\n",
	daemonUnitName:   "LoadState=loaded\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRuntimeDirectory=ezyshield\n",
}

func withUnitFixtures(t *testing.T, outputs map[string]string, systemd bool) {
	t.Helper()
	orig := showUnitProps
	showUnitProps = func(_ context.Context, unit string) (unitProps, bool, error) {
		if !systemd {
			return nil, false, nil
		}
		return parseUnitProps(outputs[unit]), true, nil
	}
	t.Cleanup(func() { showUnitProps = orig })
}

func resultsByName(rs []CheckResult) map[string]CheckResult {
	m := map[string]CheckResult{}
	for _, r := range rs {
		m[r.Name] = r
	}
	return m
}

func TestUnitHardening_HardenedUnitsPass(t *testing.T) {
	withUnitFixtures(t, hardenedShow, true)
	got := resultsByName(checkUnitHardening(context.Background()))
	for _, name := range []string{
		enforcerUnitName + ": AF_NETLINK allowed",
		enforcerUnitName + ": runtime directory",
		daemonUnitName + ": runtime directory",
	} {
		r, ok := got[name]
		if !ok || r.Status != statusPass {
			t.Fatalf("%s = %+v, want PASS", name, r)
		}
	}
}

func TestUnitHardening_StrippedNetlinkFails(t *testing.T) {
	stripped := map[string]string{
		enforcerUnitName: "LoadState=loaded\nRestrictAddressFamilies=AF_UNIX\nRuntimeDirectory=ezyshield-enforcer\n",
		daemonUnitName:   hardenedShow[daemonUnitName],
	}
	withUnitFixtures(t, stripped, true)
	got := resultsByName(checkUnitHardening(context.Background()))
	r := got[enforcerUnitName+": AF_NETLINK allowed"]
	if r.Status != statusFail {
		t.Fatalf("stripped RestrictAddressFamilies = %+v, want FAIL", r)
	}
	for _, want := range []string{"bans get recorded but never applied", "systemctl edit", "RestrictAddressFamilies=AF_UNIX AF_NETLINK"} {
		if !strings.Contains(r.Hint, want) {
			t.Fatalf("hint %q lacks %q", r.Hint, want)
		}
	}
}

func TestUnitHardening_DenyListNamingNetlinkFails(t *testing.T) {
	denied := map[string]string{
		enforcerUnitName: "LoadState=loaded\nRestrictAddressFamilies=~AF_NETLINK\nRuntimeDirectory=ezyshield-enforcer\n",
		daemonUnitName:   hardenedShow[daemonUnitName],
	}
	withUnitFixtures(t, denied, true)
	got := resultsByName(checkUnitHardening(context.Background()))
	if r := got[enforcerUnitName+": AF_NETLINK allowed"]; r.Status != statusFail {
		t.Fatalf("deny-listed AF_NETLINK = %+v, want FAIL", r)
	}
	// A deny-list of something else leaves netlink reachable.
	other := map[string]string{
		enforcerUnitName: "LoadState=loaded\nRestrictAddressFamilies=~AF_PACKET\nRuntimeDirectory=ezyshield-enforcer\n",
		daemonUnitName:   hardenedShow[daemonUnitName],
	}
	withUnitFixtures(t, other, true)
	got = resultsByName(checkUnitHardening(context.Background()))
	if r := got[enforcerUnitName+": AF_NETLINK allowed"]; r.Status != statusPass {
		t.Fatalf("deny-list without AF_NETLINK = %+v, want PASS", r)
	}
}

func TestUnitHardening_MissingRuntimeDirectoryFails(t *testing.T) {
	stripped := map[string]string{
		enforcerUnitName: hardenedShow[enforcerUnitName],
		daemonUnitName:   "LoadState=loaded\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRuntimeDirectory=\n",
	}
	withUnitFixtures(t, stripped, true)
	got := resultsByName(checkUnitHardening(context.Background()))
	r := got[daemonUnitName+": runtime directory"]
	if r.Status != statusFail {
		t.Fatalf("missing RuntimeDirectory = %+v, want FAIL", r)
	}
	if !strings.Contains(r.Hint, "RuntimeDirectory=ezyshield") || !strings.Contains(r.Hint, "systemctl edit") {
		t.Fatalf("hint %q lacks the drop-in fix", r.Hint)
	}
}

func TestUnitHardening_NonSystemdSkips(t *testing.T) {
	withUnitFixtures(t, nil, false)
	got := checkUnitHardening(context.Background())
	if len(got) != 1 || got[0].Status != statusNA {
		t.Fatalf("non-systemd host = %+v, want a single N/A", got)
	}
}

func TestUnitHardening_UnitNotInstalledSkips(t *testing.T) {
	notFound := map[string]string{
		enforcerUnitName: "LoadState=not-found\nRestrictAddressFamilies=\nRuntimeDirectory=\n",
		daemonUnitName:   hardenedShow[daemonUnitName],
	}
	withUnitFixtures(t, notFound, true)
	got := checkUnitHardening(context.Background())
	byName := resultsByName(got)
	if r := byName[enforcerUnitName+": hardening"]; r.Status != statusNA {
		t.Fatalf("not-installed unit = %+v, want N/A", r)
	}
	if r := byName[daemonUnitName+": runtime directory"]; r.Status != statusPass {
		t.Fatalf("installed unit must still be checked, got %+v", r)
	}
}

// fakeEnforcerSocket answers exactly one request with resp.
func fakeEnforcerSocket(t *testing.T, resp enforce.Response) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enf.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		var req enforce.Request
		_ = json.NewDecoder(conn).Decode(&req)
		_ = json.NewEncoder(conn).Encode(resp)
	}()
	return path
}

func TestNetlinkProbe_PassFailAndLegacyHelper(t *testing.T) {
	if r := checkEnforcerNetlinkProbe(fakeEnforcerSocket(t, enforce.Response{OK: true})); r.Status != statusPass {
		t.Fatalf("probe OK = %+v, want PASS", r)
	}
	r := checkEnforcerNetlinkProbe(fakeEnforcerSocket(t,
		enforce.Response{OK: false, Error: "netlink probe failed: operation not permitted"}))
	if r.Status != statusFail || !strings.Contains(r.Hint, "RestrictAddressFamilies") {
		t.Fatalf("probe failure = %+v, want FAIL naming the unit settings", r)
	}
	r = checkEnforcerNetlinkProbe(fakeEnforcerSocket(t,
		enforce.Response{OK: false, Error: `unknown verb "netcheck"`}))
	if r.Status != statusNA || !strings.Contains(r.Hint, "predates") {
		t.Fatalf("legacy helper = %+v, want N/A", r)
	}
	if r := checkEnforcerNetlinkProbe(filepath.Join(t.TempDir(), "missing.sock")); r.Status != statusNA {
		t.Fatalf("unreachable socket = %+v, want N/A", r)
	}
}
