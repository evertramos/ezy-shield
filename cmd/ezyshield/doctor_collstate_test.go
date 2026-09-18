// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the observation-state doctor check (issue #580): doctor asks the
// running daemon what it is actually reading, so a collector that has been
// failing for hours can no longer hide behind a page of green host checks.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// statusRespWithCollectors builds a daemon status response carrying the given
// observation state.
func statusRespWithCollectors(t *testing.T, state, detail string) daemon.SocketResponse {
	t.Helper()
	raw, err := json.Marshal(daemon.StatusData{
		Uptime:            "1h0m0s",
		EnforcementState:  string(daemon.EnfActive),
		CollectorsState:   state,
		CollectorsDetail:  detail,
		EnforcementDetail: "",
	})
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	return daemon.SocketResponse{OK: true, Data: raw}
}

func TestCheckCollectorsState_DegradedIsAFailureNamingTheCollector(t *testing.T) {
	t.Parallel()

	const detail = "docker:proxy-web is not reading (5 consecutive failures: docker: permission denied on /var/run/docker.sock)"
	sock := mockDaemonServer(t, t.TempDir(),
		statusRespWithCollectors(t, string(daemon.CollDegraded), detail),
		daemon.SocketResponse{OK: true})

	res := checkCollectorsState(sock)
	if res.Status != statusFail {
		t.Fatalf("status = %s, want FAIL (hint=%s)", res.Status, res.Hint)
	}
	if !strings.Contains(res.Hint, "docker:proxy-web") || !strings.Contains(res.Hint, "permission denied") {
		t.Errorf("hint %q must name the collector and its last error", res.Hint)
	}
}

func TestCheckCollectorsState_OKPasses(t *testing.T) {
	t.Parallel()

	sock := mockDaemonServer(t, t.TempDir(),
		statusRespWithCollectors(t, string(daemon.CollOK), ""),
		daemon.SocketResponse{OK: true})

	if res := checkCollectorsState(sock); res.Status != statusPass {
		t.Fatalf("status = %s, want PASS (hint=%s)", res.Status, res.Hint)
	}
}

func TestCheckCollectorsState_NoneWarns(t *testing.T) {
	t.Parallel()

	sock := mockDaemonServer(t, t.TempDir(),
		statusRespWithCollectors(t, string(daemon.CollNone), "no collectors configured"),
		daemon.SocketResponse{OK: true})

	if res := checkCollectorsState(sock); res.Status != statusWarn {
		t.Fatalf("status = %s, want WARN (hint=%s)", res.Status, res.Hint)
	}
}

func TestCheckCollectorsState_NAWhenTheDaemonIsNotRunning(t *testing.T) {
	t.Parallel()

	res := checkCollectorsState(filepath.Join(t.TempDir(), "absent.sock"))
	if res.Status != statusNA {
		t.Fatalf("status = %s, want N/A (hint=%s)", res.Status, res.Hint)
	}
}
