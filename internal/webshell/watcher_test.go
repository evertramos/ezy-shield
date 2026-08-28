// SPDX-License-Identifier: AGPL-3.0-only

package webshell

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newSweeper builds a Watcher over root and runs the baseline sweep, so the
// next sweep() call diffs against the initial tree state.
func newSweeper(t *testing.T, cfg Config) *Watcher {
	t.Helper()
	w, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	w.sweep(context.Background(), nil) // baseline
	return w
}

// collect runs one sweep and returns the emitted events.
func collect(w *Watcher) []Event {
	var got []Event
	w.sweep(context.Background(), func(ev Event) { got = append(got, ev) })
	return got
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestWatcher_BaselineEmitsNothing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "index.php"), "<?php echo 1;")
	w := newSweeper(t, Config{Roots: []string{root}})

	if got := collect(w); len(got) != 0 {
		t.Fatalf("pre-existing files must not fire events, got %+v", got)
	}
}

func TestWatcher_CreateDetected(t *testing.T) {
	root := t.TempDir()
	w := newSweeper(t, Config{Roots: []string{root}})

	writeFile(t, filepath.Join(root, "uploads", "shell.php"), "<?php echo \"hi\";")
	got := collect(w)
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d: %+v", len(got), got)
	}
	ev := got[0]
	if ev.Op != "created" {
		t.Errorf("Op = %q, want created", ev.Op)
	}
	if !strings.HasSuffix(ev.Path, "shell.php") {
		t.Errorf("Path = %q, want *shell.php", ev.Path)
	}
	if ev.Suspicious {
		t.Errorf("benign content flagged suspicious: %+v", ev)
	}
	if ev.Owner == "" {
		t.Errorf("Owner empty; want numeric uid on linux")
	}
	// Already-reported files must not re-fire on the next sweep.
	if again := collect(w); len(again) != 0 {
		t.Fatalf("unchanged file re-fired: %+v", again)
	}
}

func TestWatcher_SuspiciousMarkers(t *testing.T) {
	root := t.TempDir()
	w := newSweeper(t, Config{Roots: []string{root}})

	writeFile(t, filepath.Join(root, "x.php"),
		"<?php eval(base64_decode($_POST[\"c\"]));")
	got := collect(w)
	if len(got) != 1 || !got[0].Suspicious {
		t.Fatalf("want suspicious event, got %+v", got)
	}
	markers := strings.Join(got[0].Markers, ",")
	for _, m := range []string{"eval", "base64_decode", "$_POST["} {
		if !strings.Contains(markers, m) {
			t.Errorf("markers %q missing %q", markers, m)
		}
	}
}

func TestWatcher_ModifyDetected(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "app.php")
	writeFile(t, target, "<?php // original")
	w := newSweeper(t, Config{Roots: []string{root}})

	// Different size guarantees the diff fires even within the same
	// mtime granularity tick.
	writeFile(t, target, "<?php system($_REQUEST[\"cmd\"]); // injected payload")
	got := collect(w)
	if len(got) != 1 || got[0].Op != "modified" {
		t.Fatalf("want 1 modified event, got %+v", got)
	}
	if !got[0].Suspicious {
		t.Errorf("injected system() call not flagged: %+v", got[0])
	}
}

func TestWatcher_TouchOnlyModifyDetected(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "same-size.php")
	writeFile(t, target, "<?php echo 1;")
	w := newSweeper(t, Config{Roots: []string{root}})

	// Same content/size, mtime bumped: still a modification signal.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(target, future, future); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	got := collect(w)
	if len(got) != 1 || got[0].Op != "modified" {
		t.Fatalf("mtime-only change missed, got %+v", got)
	}
}

func TestWatcher_ExtensionAndIgnoreFiltering(t *testing.T) {
	root := t.TempDir()
	w := newSweeper(t, Config{
		Roots:  []string{root},
		Ignore: []string{"cache", "*.bak.php"},
	})

	writeFile(t, filepath.Join(root, "notes.txt"), "eval( in a txt is fine")
	writeFile(t, filepath.Join(root, "style.css"), "body{}")
	writeFile(t, filepath.Join(root, "cache", "tpl.php"), "<?php // churny cache")
	writeFile(t, filepath.Join(root, "old.bak.php"), "<?php // glob-ignored")
	writeFile(t, filepath.Join(root, "real.phtml"), "<?php // watched ext")

	got := collect(w)
	if len(got) != 1 || !strings.HasSuffix(got[0].Path, "real.phtml") {
		t.Fatalf("want only real.phtml, got %+v", got)
	}
}

func TestWatcher_DeletionIsSilent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "gone.php")
	writeFile(t, target, "<?php echo 1;")
	w := newSweeper(t, Config{Roots: []string{root}})

	if err := os.Remove(target); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if got := collect(w); len(got) != 0 {
		t.Fatalf("deletion fired events: %+v", got)
	}
	// Re-creation after deletion is a fresh drop → created again.
	writeFile(t, target, "<?php echo 2;")
	got := collect(w)
	if len(got) != 1 || got[0].Op != "created" {
		t.Fatalf("re-creation missed, got %+v", got)
	}
}

func TestWatcher_FloodFoldsIntoMassChange(t *testing.T) {
	root := t.TempDir()
	w := newSweeper(t, Config{Roots: []string{root}, MaxEventsPerSweep: 5})

	for i := range 12 {
		writeFile(t, filepath.Join(root, "deploy", "f"+strings.Repeat("x", i)+".php"), "<?php echo 1;")
	}
	got := collect(w)
	if len(got) != 1 || got[0].Op != "mass_change" || got[0].Count != 12 {
		t.Fatalf("want one mass_change count=12, got %+v", got)
	}
	// The flood is absorbed into tracking: no replay on the next sweep.
	if again := collect(w); len(again) != 0 {
		t.Fatalf("mass change replayed: %+v", again)
	}
}

func TestWatcher_HostileFilename(t *testing.T) {
	root := t.TempDir()
	w := newSweeper(t, Config{Roots: []string{root}})

	// Linux allows almost any byte in a name (NAME_MAX bounds one
	// component); the event must carry it capped, never crash.
	hostile := filepath.Join(root, "a\nb\x1b[31m"+strings.Repeat("z", 180)+".php")
	writeFile(t, hostile, "<?php echo 1;")
	got := collect(w)
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %+v", got)
	}
	if len(got[0].Path) > maxPathBytes {
		t.Errorf("path not capped: %d bytes", len(got[0].Path))
	}
}

func TestCapPath(t *testing.T) {
	long := strings.Repeat("p", maxPathBytes+100)
	if got := capPath(long); len(got) != maxPathBytes {
		t.Errorf("capPath len = %d, want %d", len(got), maxPathBytes)
	}
	if got := capPath("/short.php"); got != "/short.php" {
		t.Errorf("capPath mangled short path: %q", got)
	}
}

func TestWatcher_MaxFilesCap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.php"), "<?php echo 1;")
	writeFile(t, filepath.Join(root, "b.php"), "<?php echo 2;")
	w := newSweeper(t, Config{Roots: []string{root}, MaxFiles: 2})

	// Tracking is full: new files beyond the cap are not watched...
	writeFile(t, filepath.Join(root, "c.php"), "<?php echo 3;")
	if got := collect(w); len(got) != 0 {
		t.Fatalf("beyond-cap file fired events: %+v", got)
	}
	// ...but already-tracked files still report modifications.
	writeFile(t, filepath.Join(root, "a.php"), "<?php shell_exec(\"id\"); // bigger now")
	got := collect(w)
	if len(got) != 1 || got[0].Op != "modified" {
		t.Fatalf("tracked file change missed at cap, got %+v", got)
	}
}

func TestWatcher_RunHonorsContext(t *testing.T) {
	root := t.TempDir()
	w, err := New(Config{Roots: []string{root}, Interval: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, func(Event) {}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on context cancellation")
	}
}

func TestNew_RequiresRoots(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New without roots must fail")
	}
}
