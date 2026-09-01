// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for issue #580: the docker socket check must answer "can the SERVICE
// USER read this socket?", not "can whoever typed sudo doctor read it?", and
// must stay silent (N/A) when nothing in the configuration needs the socket.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePasswd writes a minimal /etc/passwd fixture.
func writePasswd(t *testing.T, lines string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(p, []byte(lines), 0o600); err != nil {
		t.Fatalf("write passwd fixture: %v", err)
	}
	return p
}

// writeGroup writes a minimal /etc/group fixture.
func writeGroup(t *testing.T, lines string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(p, []byte(lines), 0o600); err != nil {
		t.Fatalf("write group fixture: %v", err)
	}
	return p
}

// fakeStat returns a stat function serving a fixed ownership for any path.
func fakeStat(own socketOwnership) func(string) (socketOwnership, error) {
	return func(string) (socketOwnership, error) { return own, nil }
}

const (
	dockerCollectorConfig = "data_dir: /tmp/x\ncollectors:\n  - kind: docker\n    container: proxy\n    parser: nginx\n"
	fileCollectorConfig   = "data_dir: /tmp/x\ncollectors:\n  - kind: file\n    path: /var/log/nginx/access.log\n    parser: nginx\n"
	// ezyshield: uid 999, own group 999. dockerd owns the socket as root:994.
	// The 'x' password field is the standard shadow marker, not a secret. The
	// GECOS field is filled in rather than left empty so that the uid/gid
	// pair is not followed by a double colon, which the IP-hygiene gate reads
	// as an IPv6 literal.
	passwdFixture = "root:x:0:0:root:/root:/bin/bash\n" + //nolint:gosec // G101: /etc/passwd fixture, no credential
		"ezyshield:x:999:999:EzyShield service:/nonexistent:/usr/sbin/nologin\n"
)

func TestDockerSocketAccessCheck_FailsWhenServiceUserCannotReachAConfiguredSocket(t *testing.T) {
	t.Parallel()

	res := dockerSocketAccessCheck(dockerSocketAccessInputs{
		socketPath: "/var/run/docker.sock",
		passwdFile: writePasswd(t, passwdFixture),
		// The service user is in no group but its own — the field case after
		// the 'docker' group grant was revoked.
		groupFile:  writeGroup(t, "root:x:0:\ndocker:x:994:\nezyshield:x:999:\n"),
		configPath: writeTestConfig(t, dockerCollectorConfig),
		stat:       fakeStat(socketOwnership{uid: 0, gid: 994, mode: 0o660 | os.ModeSocket, isSocket: true}),
	})

	if res.Status != statusFail {
		t.Fatalf("status = %s, want FAIL (hint=%s)", res.Status, res.Hint)
	}
	for _, want := range []string{
		"ezyshield",        // whose access is missing
		"host-mounted log", // access path 1
		"socket proxy",     // access path 2
		"root-equivalent",  // the cost of access path 3
	} {
		if !strings.Contains(res.Hint, want) {
			t.Errorf("hint %q does not mention %q", res.Hint, want)
		}
	}
	// The hint explains the privilege; it does not hand out the command that
	// grants it (same guard as the docker-group check).
	if strings.Contains(res.Hint, "usermod -aG docker") {
		t.Errorf("hint hands out a bare usermod command: %q", res.Hint)
	}
}

func TestDockerSocketAccessCheck_PassesThroughGroupMembership(t *testing.T) {
	t.Parallel()

	res := dockerSocketAccessCheck(dockerSocketAccessInputs{
		socketPath: "/var/run/docker.sock",
		passwdFile: writePasswd(t, passwdFixture),
		groupFile:  writeGroup(t, "root:x:0:\ndocker:x:994:ezyshield\nezyshield:x:999:\n"),
		configPath: writeTestConfig(t, dockerCollectorConfig),
		stat:       fakeStat(socketOwnership{uid: 0, gid: 994, mode: 0o660 | os.ModeSocket, isSocket: true}),
	})

	if res.Status != statusPass {
		t.Fatalf("status = %s, want PASS (hint=%s)", res.Status, res.Hint)
	}
}

func TestDockerSocketAccessCheck_PassesWhenTheSocketIsOwnedByTheServiceUser(t *testing.T) {
	t.Parallel()

	// A socket proxy running as the service user (the access path #579 makes
	// configurable) grants access without any group.
	res := dockerSocketAccessCheck(dockerSocketAccessInputs{
		socketPath: "/run/docker-proxy.sock",
		passwdFile: writePasswd(t, passwdFixture),
		groupFile:  writeGroup(t, "root:x:0:\ndocker:x:994:\nezyshield:x:999:\n"),
		configPath: writeTestConfig(t, dockerCollectorConfig),
		stat:       fakeStat(socketOwnership{uid: 999, gid: 999, mode: 0o600 | os.ModeSocket, isSocket: true}),
	})

	if res.Status != statusPass {
		t.Fatalf("status = %s, want PASS (hint=%s)", res.Status, res.Hint)
	}
}

func TestDockerSocketAccessCheck_NAWhenNothingNeedsTheSocket(t *testing.T) {
	t.Parallel()

	res := dockerSocketAccessCheck(dockerSocketAccessInputs{
		socketPath: "/var/run/docker.sock",
		passwdFile: writePasswd(t, passwdFixture),
		groupFile:  writeGroup(t, "docker:x:994:\n"),
		configPath: writeTestConfig(t, fileCollectorConfig),
		stat: func(string) (socketOwnership, error) {
			t.Error("an unconfigured socket must not even be stat'ed")
			return socketOwnership{}, nil
		},
	})

	if res.Status != statusNA {
		t.Fatalf("status = %s, want N/A (hint=%s)", res.Status, res.Hint)
	}
}

func TestDockerSocketAccessCheck_NAWhenDockerIsAbsent(t *testing.T) {
	t.Parallel()

	res := dockerSocketAccessCheck(dockerSocketAccessInputs{
		socketPath: "/var/run/docker.sock",
		passwdFile: writePasswd(t, passwdFixture),
		groupFile:  writeGroup(t, "root:x:0:\n"),
		configPath: writeTestConfig(t, dockerCollectorConfig),
		stat: func(string) (socketOwnership, error) {
			return socketOwnership{}, fs.ErrNotExist
		},
	})

	if res.Status != statusNA {
		t.Fatalf("status = %s, want N/A (hint=%s)", res.Status, res.Hint)
	}
}

func TestDockerSocketAccessCheck_FailsWhenThePathItselfIsClosed(t *testing.T) {
	t.Parallel()

	// EACCES on stat: a parent directory denies traversal. The daemon hits
	// the same wall, so this is a FAIL, not the "Docker absent" N/A.
	res := dockerSocketAccessCheck(dockerSocketAccessInputs{
		socketPath: "/var/run/docker.sock",
		passwdFile: writePasswd(t, passwdFixture),
		groupFile:  writeGroup(t, "root:x:0:\n"),
		configPath: writeTestConfig(t, dockerCollectorConfig),
		stat: func(string) (socketOwnership, error) {
			return socketOwnership{}, fs.ErrPermission
		},
	})

	if res.Status != statusFail {
		t.Fatalf("status = %s, want FAIL (hint=%s)", res.Status, res.Hint)
	}
}

func TestDockerSocketAccessCheck_NAWhenTheServiceUserDoesNotExist(t *testing.T) {
	t.Parallel()

	res := dockerSocketAccessCheck(dockerSocketAccessInputs{
		socketPath: "/var/run/docker.sock",
		passwdFile: writePasswd(t, "root:x:0:0:root:/root:/bin/bash\n"),
		groupFile:  writeGroup(t, "docker:x:994:\n"),
		configPath: writeTestConfig(t, dockerCollectorConfig),
		stat:       fakeStat(socketOwnership{uid: 0, gid: 994, mode: 0o660 | os.ModeSocket, isSocket: true}),
	})

	if res.Status != statusNA {
		t.Fatalf("status = %s, want N/A (hint=%s)", res.Status, res.Hint)
	}
	if !strings.Contains(res.Hint, serviceUser) {
		t.Errorf("hint %q should name the user it could not resolve", res.Hint)
	}
}

// TestSocketReadWritable_AppliesTheKernelRule pins the permission arithmetic,
// including the property that trips people up: the classes do not fall
// through, so an owner denied by the owner bits stays denied even when the
// other bits are open.
func TestSocketReadWritable_AppliesTheKernelRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		own  socketOwnership
		ids  serviceUserIDs
		want bool
	}{
		{"owner rw", socketOwnership{uid: 999, gid: 0, mode: 0o600}, serviceUserIDs{uid: 999, gids: []uint32{999}}, true},
		{"owner with no owner bits", socketOwnership{uid: 999, gid: 0, mode: 0o006}, serviceUserIDs{uid: 999, gids: []uint32{999}}, false},
		{"group member rw", socketOwnership{uid: 0, gid: 994, mode: 0o660}, serviceUserIDs{uid: 999, gids: []uint32{999, 994}}, true},
		{"group member, read only", socketOwnership{uid: 0, gid: 994, mode: 0o640}, serviceUserIDs{uid: 999, gids: []uint32{999, 994}}, false},
		{"not a member, world rw", socketOwnership{uid: 0, gid: 994, mode: 0o666}, serviceUserIDs{uid: 999, gids: []uint32{999}}, true},
		{"not a member, group rw only", socketOwnership{uid: 0, gid: 994, mode: 0o660}, serviceUserIDs{uid: 999, gids: []uint32{999}}, false},
		{"root bypasses the mode bits", socketOwnership{uid: 0, gid: 0, mode: 0o600}, serviceUserIDs{uid: 0, gids: []uint32{0}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := socketReadWritable(tc.own, tc.ids); got != tc.want {
				t.Errorf("socketReadWritable = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestServiceUserIdentity_ResolvesPrimaryAndSupplementaryGroups covers the
// passwd/group parsing the check depends on: no cgo, no root, no NSS.
func TestServiceUserIdentity_ResolvesPrimaryAndSupplementaryGroups(t *testing.T) {
	t.Parallel()

	ids, err := serviceUserIdentity(
		writePasswd(t, passwdFixture),
		writeGroup(t, "root:x:0:\ndocker:x:994:someone,ezyshield\nadm:x:4:ezyshield\nezyshield:x:999:\n"),
		serviceUser)
	if err != nil {
		t.Fatalf("serviceUserIdentity: %v", err)
	}
	if ids.uid != 999 {
		t.Errorf("uid = %d, want 999", ids.uid)
	}
	for _, want := range []uint32{999, 994, 4} {
		var found bool
		for _, g := range ids.gids {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("gid %d missing from %v", want, ids.gids)
		}
	}
}

func TestServiceUserIdentity_UnknownUserIsAnError(t *testing.T) {
	t.Parallel()

	_, err := serviceUserIdentity(
		writePasswd(t, "root:x:0:0:root:/root:/bin/bash\n"),
		writeGroup(t, "root:x:0:\n"),
		serviceUser)
	if err == nil {
		t.Fatal("an unknown service user must be reported, not assumed accessible")
	}
}

func TestPasswdFileIDs_MissingFile(t *testing.T) {
	t.Parallel()

	_, _, err := passwdFileIDs(filepath.Join(t.TempDir(), "absent"), serviceUser)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want a not-exist error", err)
	}
}
