package collector

// Regression test for the graceful-drain half of issue #358's send fix: with
// ctx already cancelled but the pipeline still consuming (SIGTERM drain),
// both select cases are ready and Go picks uniformly — a naive two-case
// select randomly dropped ~half of the deliverable tail lines. The
// non-blocking first attempt must deliver EVERY line while buffer space
// exists; only a full channel with a dead consumer may drop.

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestDrainLines_GracefulDrainDeliversBufferedLines(t *testing.T) {
	t.Parallel()

	const n = 50
	var content []byte
	for i := 0; i < n; i++ {
		content = append(content, []byte("line\n")...)
	}
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // SIGTERM drain: collectors' ctx is done, pipeline still reads

	out := make(chan sdk.RawLine, n+8) // ample buffer — every line is deliverable
	asm := newLineAssembler(maxStreamLineBytes)

	done := make(chan error, 1)
	go func() { done <- drainLines(ctx, f, asm, "file:"+path, out, slog.Default()) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drainLines wedged")
	}

	if got := len(out); got != n {
		t.Fatalf("graceful drain delivered %d/%d lines — the canceled-ctx select is dropping deliverable lines", got, n)
	}
}
