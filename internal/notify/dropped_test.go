// SPDX-License-Identifier: AGPL-3.0-only

package notify_test

import (
	"context"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// TestDispatcher_DroppedSendsAreCounted (issue #613): a suppressed send is
// observable — the daemon exposes this counter as a metric.
func TestDispatcher_DroppedSendsAreCounted(t *testing.T) {
	n := &stubNotifier{name: "phone"}
	d := notify.New([]sdk.Notifier{n}, 1, time.Hour, nil)
	_ = d.Send(context.Background(), makeMsg("info", "first"))
	_ = d.Send(context.Background(), makeMsg("info", "second")) // over quota
	if got := d.Dropped(); got != 1 {
		t.Fatalf("Dropped() = %d, want 1", got)
	}
	if !d.AcceptsCritical() {
		t.Fatalf("a channel with no severity filter must accept critical")
	}
	filtered := notify.New([]sdk.Notifier{n}, 5, time.Hour, map[string][]string{"phone": {"warn"}})
	if filtered.AcceptsCritical() {
		t.Fatalf("a warn-only channel set must report that nothing accepts critical")
	}
}
