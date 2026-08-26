// SPDX-License-Identifier: AGPL-3.0-only

package unitcheck

// Tests for the systemd unit hardening checks (issue #213; moved from
// cmd/ezyshield with the package extraction in #563), driven by fixture
// `systemctl show` outputs injected through ShowUnitProps — no systemd
// needed on the test host.

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
	EnforcerUnitName: "LoadState=loaded\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\nRuntimeDirectory=ezyshield-enforcer\n",
	DaemonUnitName:   "LoadState=loaded\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRuntimeDirectory=ezyshield\n",
}

func withUnitFixtures(t *testing.T, outputs map[string]string, systemd bool) {
	t.Helper()
	orig := ShowUnitProps
	ShowUnitProps = func(_ context.Context, unit string) (map[string]string, bool, error) {
		if !systemd {
			return nil, false, nil
		}
		return parseUnitProps(outputs[unit]), true, nil
	}
	t.Cleanup(func() { ShowUnitProps = orig })
}

func resultsByName(rs []Result) map[string]Result {
	m := map[string]Result{}
	for _, r := range rs {
		m[r.Name] = r
	}
	return m
}

func TestUnitHardening_HardenedUnitsPass(t *testing.T) {
	withUnitFixtures(t, hardenedShow, true)
	got := resultsByName(UnitHardening(context.Background()))
	for _, name := range []string{
		EnforcerUnitName + ": AF_NETLINK allowed",
		EnforcerUnitName + ": runtime directory",
		DaemonUnitName + ": runtime directory",
	} {
		r, ok := got[name]
		if !ok || r.Status != StatusPass {
			t.Fatalf("%s = %+v, want pass", name, r)
		}
	}
}

func TestUnitHardening_StrippedNetlinkFails(t *testing.T) {
	stripped := map[string]string{
		EnforcerUnitName: "LoadState=loaded\nRestrictAddressFamilies=AF_UNIX\nRuntimeDirectory=ezyshield-enforcer\n",
		DaemonUnitName:   hardenedShow[DaemonUnitName],
	}
	withUnitFixtures(t, stripped, true)
	got := resultsByName(UnitHardening(context.Background()))
	r := got[EnforcerUnitName+": AF_NETLINK allowed"]
	if r.Status != StatusFail {
		t.Fatalf("stripped RestrictAddressFamilies = %+v, want fail", r)
	}
	for _, want := range []string{"bans get recorded but never applied", "systemctl edit", "RestrictAddressFamilies=AF_UNIX AF_NETLINK"} {
		if !strings.Contains(r.Hint, want) {
			t.Fatalf("hint %q lacks %q", r.Hint, want)
		}
	}
}

func TestUnitHardening_DenyListNamingNetlinkFails(t *testing.T) {
	denied := map[string]string{
		EnforcerUnitName: "LoadState=loaded\nRestrictAddressFamilies=~AF_NETLINK\nRuntimeDirectory=ezyshield-enforcer\n",
		DaemonUnitName:   hardenedShow[DaemonUnitName],
	}
	withUnitFixtures(t, denied, true)
	got := resultsByName(UnitHardening(context.Background()))
	if r := got[EnforcerUnitName+": AF_NETLINK allowed"]; r.Status != StatusFail {
		t.Fatalf("deny-listed AF_NETLINK = %+v, want fail", r)
	}
	// A deny-list of something else leaves netlink reachable.
	other := map[string]string{
		EnforcerUnitName: "LoadState=loaded\nRestrictAddressFamilies=~AF_PACKET\nRuntimeDirectory=ezyshield-enforcer\n",
		DaemonUnitName:   hardenedShow[DaemonUnitName],
	}
	withUnitFixtures(t, other, true)
	got = resultsByName(UnitHardening(context.Background()))
	if r := got[EnforcerUnitName+": AF_NETLINK allowed"]; r.Status != StatusPass {
		t.Fatalf("deny-list without AF_NETLINK = %+v, want pass", r)
	}
}

func TestUnitHardening_MissingRuntimeDirectoryFails(t *testing.T) {
	stripped := map[string]string{
		EnforcerUnitName: hardenedShow[EnforcerUnitName],
		DaemonUnitName:   "LoadState=loaded\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRuntimeDirectory=\n",
	}
	withUnitFixtures(t, stripped, true)
	got := resultsByName(UnitHardening(context.Background()))
	r := got[DaemonUnitName+": runtime directory"]
	if r.Status != StatusFail {
		t.Fatalf("missing RuntimeDirectory = %+v, want fail", r)
	}
	if !strings.Contains(r.Hint, "RuntimeDirectory=ezyshield") || !strings.Contains(r.Hint, "systemctl edit") {
		t.Fatalf("hint %q lacks the drop-in fix", r.Hint)
	}
}

func TestUnitHardening_NonSystemdSkips(t *testing.T) {
	withUnitFixtures(t, nil, false)
	got := UnitHardening(context.Background())
	if len(got) != 1 || got[0].Status != StatusNA {
		t.Fatalf("non-systemd host = %+v, want a single N/A", got)
	}
}

func TestUnitHardening_UnitNotInstalledSkips(t *testing.T) {
	notFound := map[string]string{
		EnforcerUnitName: "LoadState=not-found\nRestrictAddressFamilies=\nRuntimeDirectory=\n",
		DaemonUnitName:   hardenedShow[DaemonUnitName],
	}
	withUnitFixtures(t, notFound, true)
	got := UnitHardening(context.Background())
	byName := resultsByName(got)
	if r := byName[EnforcerUnitName+": hardening"]; r.Status != StatusNA {
		t.Fatalf("not-installed unit = %+v, want N/A", r)
	}
	if r := byName[DaemonUnitName+": runtime directory"]; r.Status != StatusPass {
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
	ctx := context.Background()
	if r := NetlinkProbe(ctx, fakeEnforcerSocket(t, enforce.Response{OK: true})); r.Status != StatusPass {
		t.Fatalf("probe OK = %+v, want pass", r)
	}
	r := NetlinkProbe(ctx, fakeEnforcerSocket(t,
		enforce.Response{OK: false, Error: "netlink probe failed: operation not permitted"}))
	if r.Status != StatusFail || !strings.Contains(r.Hint, "RestrictAddressFamilies") {
		t.Fatalf("probe failure = %+v, want fail naming the unit settings", r)
	}
	r = NetlinkProbe(ctx, fakeEnforcerSocket(t,
		enforce.Response{OK: false, Error: `unknown verb "netcheck"`}))
	if r.Status != StatusNA || !strings.Contains(r.Hint, "predates") {
		t.Fatalf("legacy helper = %+v, want N/A", r)
	}
	if r := NetlinkProbe(ctx, filepath.Join(t.TempDir(), "missing.sock")); r.Status != StatusNA {
		t.Fatalf("unreachable socket = %+v, want N/A", r)
	}
}

func TestFailures_FiltersHardFailuresOnly(t *testing.T) {
	t.Parallel()
	in := []Result{
		{Name: "a", Status: StatusPass},
		{Name: "b", Status: StatusFail},
		{Name: "c", Status: StatusNA},
		{Name: "d", Status: StatusWarn},
	}
	got := Failures(in)
	if len(got) != 1 || got[0].Name != "b" {
		t.Fatalf("Failures = %+v, want only the fail", got)
	}
}
