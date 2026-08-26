// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for issue #455: `doctor` printed [PASS] journald: readable
// by probing as the invoking user (root under sudo) while the daemon's
// service user could not read the journal at all (issue #454).

func fakeUser(name, uid, gid string) *user.User {
	return &user.User{Username: name, Uid: uid, Gid: gid}
}

func TestJournalProbeIdentity(t *testing.T) {
	failCurrent := func() (*user.User, error) { return nil, errors.New("no current user") }
	noGroups := func(*user.User) ([]string, error) { return nil, errors.New("no groups") }

	tests := []struct {
		name       string
		euid       int
		current    func() (*user.User, error)
		lookup     func(string) (*user.User, error)
		groupIDs   func(*user.User) ([]string, error)
		wantLabel  string
		wantDrop   bool
		wantUID    uint32
		wantGID    uint32
		wantGroups []uint32
		wantNote   string // substring; "" means any (unchecked)
	}{
		{
			name:      "unprivileged evaluates the invoker and says how to do better",
			euid:      1000,
			current:   func() (*user.User, error) { return fakeUser("testadmin", "1000", "1000"), nil },
			lookup:    func(string) (*user.User, error) { t.Fatal("lookup must not be called unprivileged"); return nil, nil },
			groupIDs:  noGroups,
			wantLabel: "testadmin",
			wantDrop:  false,
			wantNote:  "sudo",
		},
		{
			name:      "unprivileged with unknown current user keeps a generic label",
			euid:      1000,
			current:   failCurrent,
			lookup:    func(string) (*user.User, error) { return nil, errors.New("unused") },
			groupIDs:  noGroups,
			wantLabel: "current user",
			wantDrop:  false,
			wantNote:  "sudo",
		},
		{
			name:    "root drops to the service user with supplementary groups",
			euid:    0,
			current: failCurrent,
			lookup: func(name string) (*user.User, error) {
				if name != journaldServiceUser {
					return nil, errors.New("unexpected lookup: " + name)
				}
				return fakeUser(journaldServiceUser, "999", "989"), nil
			},
			// "bogus" must be skipped, not abort the whole resolution.
			groupIDs:   func(*user.User) ([]string, error) { return []string{"989", "4", "bogus"}, nil },
			wantLabel:  journaldServiceUser,
			wantDrop:   true,
			wantUID:    999,
			wantGID:    989,
			wantGroups: []uint32{989, 4},
		},
		{
			name:      "root without the service user degrades loudly to root",
			euid:      0,
			current:   failCurrent,
			lookup:    func(string) (*user.User, error) { return nil, user.UnknownUserError(journaldServiceUser) },
			groupIDs:  noGroups,
			wantLabel: "root",
			wantDrop:  false,
			wantNote:  "not found",
		},
		{
			name:      "unparsable uid degrades loudly to root",
			euid:      0,
			current:   failCurrent,
			lookup:    func(string) (*user.User, error) { return fakeUser(journaldServiceUser, "notanumber", "989"), nil },
			groupIDs:  noGroups,
			wantLabel: "root",
			wantDrop:  false,
			wantNote:  "uid/gid",
		},
		{
			name:    "group resolution failure still drops with uid/gid only",
			euid:    0,
			current: failCurrent,
			lookup:  func(string) (*user.User, error) { return fakeUser(journaldServiceUser, "999", "989"), nil },
			groupIDs: func(*user.User) ([]string, error) {
				return nil, errors.New("group db unavailable")
			},
			wantLabel:  journaldServiceUser,
			wantDrop:   true,
			wantUID:    999,
			wantGID:    989,
			wantGroups: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := journalProbeIdentity(tt.euid, tt.current, tt.lookup, tt.groupIDs)
			if id.label != tt.wantLabel {
				t.Errorf("label = %q, want %q", id.label, tt.wantLabel)
			}
			if id.drop != tt.wantDrop {
				t.Errorf("drop = %v, want %v", id.drop, tt.wantDrop)
			}
			if id.drop {
				if id.uid != tt.wantUID || id.gid != tt.wantGID {
					t.Errorf("uid:gid = %d:%d, want %d:%d", id.uid, id.gid, tt.wantUID, tt.wantGID)
				}
				if len(id.groups) != len(tt.wantGroups) {
					t.Errorf("groups = %v, want %v", id.groups, tt.wantGroups)
				} else {
					for i, g := range tt.wantGroups {
						if id.groups[i] != g {
							t.Errorf("groups = %v, want %v", id.groups, tt.wantGroups)
							break
						}
					}
				}
			}
			if tt.wantNote != "" && !strings.Contains(id.note, tt.wantNote) {
				t.Errorf("note = %q, want it to mention %q", id.note, tt.wantNote)
			}
		})
	}
}

// fakeJournalctl writes an executable stub that prints msg to stderr and
// exits with code.
func fakeJournalctl(t *testing.T, code int, msg string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "journalctl")
	script := "#!/bin/sh\n"
	if msg != "" {
		script += "echo '" + msg + "' >&2\n"
	}
	script += "exit " + map[int]string{0: "0", 1: "1"}[code] + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil { //nolint:gosec // test stub
		t.Fatalf("writing stub: %v", err)
	}
	return path
}

func TestProbeJournalReadable_DenialNamesUserAndRemediation(t *testing.T) {
	id := journalProbeID{label: journaldServiceUser} // no drop: the stub already fails
	res := probeJournalReadable(id, fakeJournalctl(t, 1, "No journal files were opened due to insufficient permissions."))

	if res.Status != statusFail {
		t.Fatalf("status = %v, want FAIL", res.Status)
	}
	if !strings.Contains(res.Name, "(as "+journaldServiceUser+")") {
		t.Errorf("check name %q does not say whose access was evaluated", res.Name)
	}
	for _, want := range []string{
		"failed as " + journaldServiceUser,
		"insufficient permissions",
		"usermod -aG systemd-journal " + journaldServiceUser,
	} {
		if !strings.Contains(res.Hint, want) {
			t.Errorf("hint %q missing %q", res.Hint, want)
		}
	}
}

func TestProbeJournalReadable_PassCarriesIdentityAndNote(t *testing.T) {
	id := journalProbeID{label: "testadmin", note: "run doctor with sudo to evaluate the service user"}
	res := probeJournalReadable(id, fakeJournalctl(t, 0, ""))

	if res.Status != statusPass {
		t.Fatalf("status = %v, want PASS (hint: %s)", res.Status, res.Hint)
	}
	if !strings.Contains(res.Name, "(as testadmin)") {
		t.Errorf("check name %q does not say whose access was evaluated", res.Name)
	}
	if !strings.Contains(res.Hint, "sudo") {
		t.Errorf("degraded-identity note lost: hint = %q", res.Hint)
	}
}

func TestProbeJournalReadable_MissingJournalctl(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty dir: LookPath("journalctl") fails
	res := probeJournalReadable(journalProbeID{label: "root"}, "")
	if res.Status != statusFail {
		t.Fatalf("status = %v, want FAIL", res.Status)
	}
	if !strings.Contains(res.Hint, "journalctl not found") {
		t.Errorf("hint = %q, want the not-found message", res.Hint)
	}
}
