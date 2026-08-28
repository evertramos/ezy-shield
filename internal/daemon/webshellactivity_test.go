// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"strings"
	"testing"
)

// TestReportWebshellActivity_AuditAndZeroBans pins the safety property of
// the tripwire (issue #221): an observation is audited, but NEVER creates a
// ban — there is no remote IP on a filesystem event.
func TestReportWebshellActivity_AuditAndZeroBans(t *testing.T) {
	d := newTestDaemonForSocket(t, true) // armed on purpose: still no ban
	ctx := context.Background()

	d.ReportWebshellActivity(ctx, WebshellReport{
		Path:       "/var/www/html/uploads/x.php",
		Op:         "created",
		Owner:      "33",
		Size:       512,
		Suspicious: true,
		Markers:    []string{"eval", "base64_decode"},
	})
	d.ReportWebshellActivity(ctx, WebshellReport{
		Op:    "mass_change",
		Count: 42,
	})

	entries, err := d.store.ListAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	var got []string
	for _, e := range entries {
		if e.Op == "webshell_watch" {
			got = append(got, e.Reason)
		}
	}
	if len(got) != 2 {
		t.Fatalf("want 2 webshell_watch audit rows, got %d (%v)", len(got), got)
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{"x.php", "uid 33", "SUSPICIOUS", "eval", "42 files"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit rows missing %q:\n%s", want, joined)
		}
	}

	bans, err := d.store.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 0 {
		t.Fatalf("webshell observation must never ban, got %d active bans", len(bans))
	}
}

// TestRunWebshellActivity_NilIsDisabled pins that an absent injection means
// the feature is fully off (no goroutine work, no panic).
func TestRunWebshellActivity_NilIsDisabled(t *testing.T) {
	d := newTestDaemonForSocket(t, false)
	d.runWebshellActivity(context.Background()) // must return immediately
}

// TestRunWebshellActivity_DeliversReports pins the injection plumbing: the
// wired function receives a report callback that lands in the audit log.
func TestRunWebshellActivity_DeliversReports(t *testing.T) {
	d := newTestDaemonForSocket(t, false)
	d.webshellActivity = func(ctx context.Context, report func(WebshellReport)) {
		report(WebshellReport{Path: "/srv/www/drop.php", Op: "created", Owner: "0", Size: 9})
	}
	ctx := context.Background()
	d.runWebshellActivity(ctx)

	entries, err := d.store.ListAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	for _, e := range entries {
		if e.Op == "webshell_watch" && strings.Contains(e.Reason, "drop.php") {
			return
		}
	}
	t.Fatalf("injected report did not reach the audit log: %+v", entries)
}
