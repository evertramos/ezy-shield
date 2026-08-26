// SPDX-License-Identifier: AGPL-3.0-only

package collector

// Regression test for issue #358 item 1: collector channel sends must race
// ctx cancellation. A plain blocking send wedged the collector goroutine
// forever when the pipeline exited early (SIGINT with lines still buffered),
// and the daemon's rawLines-closing goroutine never completed.

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestDrainLines_CanceledContextDoesNotWedge(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte("line one\nline two\nline three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the pipeline is already gone

	// Unbuffered channel with NO reader: pre-fix this send blocks forever.
	out := make(chan sdk.RawLine)
	asm := newLineAssembler(maxStreamLineBytes)

	done := make(chan error, 1)
	go func() {
		done <- drainLines(ctx, f, asm, "file:"+path, out, slog.Default())
	}()

	select {
	case <-done:
		// Returned promptly — the send raced cancellation instead of blocking.
	case <-time.After(2 * time.Second):
		t.Fatal("drainLines wedged on a blocking send after ctx cancellation (issue #358)")
	}
}
