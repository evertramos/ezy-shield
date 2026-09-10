// SPDX-License-Identifier: AGPL-3.0-only

package collector_test

// Regression test for issue #599: journalctl follow mode must start at the
// live tail (-n 0). Without it, every daemon restart replayed the last 10
// journal entries as fresh evidence.

import (
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/collector"
)

func TestJournalctlFollowArgs_NoBacklog(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		match []string
	}{
		{"unit", []string{"-u", "sshd"}},
		{"container", []string{"CONTAINER_NAME=proxy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := collector.JournalctlFollowArgs(tc.match...)
			joined := " " + strings.Join(args, " ") + " "
			for _, want := range []string{" -n 0 ", " -f ", " -o cat ", " --no-pager "} {
				if !strings.Contains(joined, want) {
					t.Errorf("args %v missing %q", args, want)
				}
			}
			// The match comes first so a future flag cannot be swallowed
			// as a match value; -n 0 must precede -f.
			if !strings.HasPrefix(joined, " "+strings.Join(tc.match, " ")+" ") {
				t.Errorf("args %v must start with the match %v", args, tc.match)
			}
			if strings.Index(joined, " -n 0 ") > strings.Index(joined, " -f ") {
				t.Errorf("args %v: -n 0 must precede -f", args)
			}
		})
	}
}
