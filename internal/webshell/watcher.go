// Package webshell implements the webshell-drop tripwire (issue #221): a
// filesystem watch over configured web roots for new or modified files with
// executable web extensions — the artifact a log parser can never see when
// an upload bypassed the logs.
//
// Detection mechanism: bounded mtime/size polling sweeps (default 10s),
// consistent with ADR-0004's stat-based-polling preference — dependency-
// free, immune to inotify watch-limit exhaustion, and trivially testable.
// The ≤1-sweep detection latency is fine for a tripwire.
//
// Purely observational: events go to a sink; the daemon audits/streams/
// notifies. File CONTENT is hostile data — the heuristic scan is read-only
// and size-capped, and nothing from a file is ever executed, interpolated,
// or logged raw.
package webshell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Bounds: a watcher over attacker-writable trees must never grow without
// limit or amplify a deploy into a notification storm.
const (
	// DefaultInterval is the sweep cadence.
	DefaultInterval = 10 * time.Second
	// DefaultMaxFiles caps the tracked-state map; trees larger than this
	// are reported once and the excess is not tracked.
	DefaultMaxFiles = 50_000
	// DefaultMaxEventsPerSweep folds a mass change (a deploy) into ONE
	// summary event instead of per-file noise.
	DefaultMaxEventsPerSweep = 20
	// maxScanBytes bounds the read-only content heuristic.
	maxScanBytes = 32 * 1024
	// maxPathBytes caps the path stored on events.
	maxPathBytes = 256
)

// DefaultExtensions are the executable web extensions watched when the
// config lists none.
var DefaultExtensions = []string{".php", ".phtml", ".php5", ".php7", ".phar"}

// suspiciousMarkers are high-signal webshell constructs looked for in the
// first maxScanBytes of a changed file. Presence sets the Suspicious flag —
// a heuristic tripwire, NOT a verdict (documented honestly in the guide).
var suspiciousMarkers = []string{
	"eval(", "base64_decode", "gzinflate", "str_rot13",
	"shell_exec", "system(", "passthru", "proc_open", "popen(",
	"assert(", "move_uploaded_file", "$_POST[", "$_REQUEST[",
}

// Event is one observed filesystem change in a watched web root.
type Event struct {
	// Path is the changed file (capped; may contain hostile bytes — the
	// daemon sanitizes at render time).
	Path string
	// Op is "created", "modified", or "mass_change" (flood summary).
	Op string
	// Owner is the file's numeric uid (v1 keeps it resolution-free).
	Owner string
	// Size is the file size at observation.
	Size int64
	// Suspicious is the content-heuristic flag; Markers lists what matched.
	Suspicious bool
	Markers    []string
	// Count is only set on "mass_change": how many files changed in the
	// sweep (individual events suppressed).
	Count int
}

// Config bounds and targets one watcher.
type Config struct {
	// Roots are the web-root directories to sweep (required).
	Roots []string
	// Extensions overrides DefaultExtensions (leading dot, lower-case).
	Extensions []string
	// Ignore lists path patterns to skip (path.Match globs on the full
	// path; plain text matches as substring) — cache/upload dirs that
	// legitimately churn.
	Ignore []string
	// Interval overrides DefaultInterval (tests).
	Interval time.Duration
	// MaxFiles / MaxEventsPerSweep override the bounds (0 = defaults).
	MaxFiles          int
	MaxEventsPerSweep int
	// Logger receives debug/warn messages. If nil, slog.Default() is used.
	Logger *slog.Logger
}

type fileState struct {
	modTime time.Time
	size    int64
}

// Watcher sweeps the configured roots and reports changes.
type Watcher struct {
	cfg    Config
	exts   map[string]bool
	logger *slog.Logger
	// known maps path → last seen state. Populated by the baseline sweep
	// (which emits nothing) and diffed on every sweep after.
	known map[string]fileState
	// capWarned dedups the tracked-files-cap warning.
	capWarned bool
}

// New builds a Watcher; Config.Roots must be non-empty.
func New(cfg Config) (*Watcher, error) {
	if len(cfg.Roots) == 0 {
		return nil, fmt.Errorf("webshell: at least one root is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = DefaultMaxFiles
	}
	if cfg.MaxEventsPerSweep <= 0 {
		cfg.MaxEventsPerSweep = DefaultMaxEventsPerSweep
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	exts := map[string]bool{}
	list := cfg.Extensions
	if len(list) == 0 {
		list = DefaultExtensions
	}
	for _, e := range list {
		exts[strings.ToLower(e)] = true
	}
	return &Watcher{cfg: cfg, exts: exts, logger: cfg.Logger, known: map[string]fileState{}}, nil
}

// Run sweeps until ctx is done, reporting changes to sink. The first sweep
// is the baseline (no events). Always returns nil on cancellation.
func (w *Watcher) Run(ctx context.Context, sink func(Event)) error {
	w.sweep(ctx, nil) // baseline
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			w.sweep(ctx, sink)
		}
	}
}

// sweep walks every root, diffs against known state, and (when sink is
// non-nil) emits bounded events.
func (w *Watcher) sweep(ctx context.Context, sink func(Event)) {
	var changes []Event
	seen := map[string]bool{}
	for _, root := range w.cfg.Roots {
		w.sweepRoot(ctx, root, seen, &changes)
	}
	// Deleted files just leave tracking (deletion is not a drop signal).
	for p := range w.known {
		if !seen[p] {
			delete(w.known, p)
		}
	}
	if sink == nil || len(changes) == 0 {
		return
	}
	if len(changes) > w.cfg.MaxEventsPerSweep {
		// A deploy: one honest summary beats a notification storm.
		sink(Event{Op: "mass_change", Count: len(changes)})
		return
	}
	for _, ev := range changes {
		sink(ev)
	}
}

func (w *Watcher) sweepRoot(ctx context.Context, root string, seen map[string]bool, changes *[]Event) {
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			return nil // unreadable entries are skipped, never fatal
		}
		if d.IsDir() {
			if w.ignored(p) {
				return filepath.SkipDir
			}
			return nil
		}
		if !w.exts[strings.ToLower(filepath.Ext(p))] || w.ignored(p) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if len(w.known) >= w.cfg.MaxFiles {
			if !w.capWarned {
				w.capWarned = true
				w.logger.Warn("webshell: tracked-files cap reached; additional files are not watched",
					"cap", w.cfg.MaxFiles)
			}
			if _, tracked := w.known[p]; !tracked {
				return nil
			}
		}
		seen[p] = true
		st := fileState{modTime: info.ModTime(), size: info.Size()}
		prev, existed := w.known[p]
		w.known[p] = st
		switch {
		case !existed:
			*changes = append(*changes, w.buildEvent(p, "created", info))
		case !prev.modTime.Equal(st.modTime) || prev.size != st.size:
			*changes = append(*changes, w.buildEvent(p, "modified", info))
		}
		return nil
	})
	if err != nil {
		w.logger.Debug("webshell: sweep error", "root", root, "err", err)
	}
}

// buildEvent assembles the event, including the read-only content heuristic.
func (w *Watcher) buildEvent(p, op string, info fs.FileInfo) Event {
	ev := Event{
		Path:  capPath(p),
		Op:    op,
		Size:  info.Size(),
		Owner: fileOwner(info),
	}
	ev.Suspicious, ev.Markers = scanContent(p)
	return ev
}

// scanContent reads at most maxScanBytes of the file and reports which
// suspicious constructs appear. The content is HOSTILE: it is only byte-
// compared against fixed markers — never executed, parsed, or logged.
func scanContent(p string) (bool, []string) {
	f, err := os.Open(p) //nolint:gosec // path comes from the operator-configured web root walk
	if err != nil {
		return false, nil
	}
	defer f.Close() //nolint:errcheck
	buf, err := io.ReadAll(io.LimitReader(f, maxScanBytes))
	if err != nil {
		return false, nil
	}
	var markers []string
	for _, m := range suspiciousMarkers {
		if bytes.Contains(buf, []byte(m)) {
			markers = append(markers, strings.TrimSuffix(m, "("))
		}
	}
	return len(markers) > 0, markers
}

// fileOwner returns the file's numeric uid as a string ("" off-linux).
func fileOwner(info fs.FileInfo) string {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(st.Uid), 10)
	}
	return ""
}

// ignored reports whether p matches any ignore pattern (path.Match glob,
// or substring when the pattern has no glob metacharacters).
func (w *Watcher) ignored(p string) bool {
	for _, pat := range w.cfg.Ignore {
		if pat == "" {
			continue
		}
		if strings.ContainsAny(pat, "*?[") {
			if ok, err := path.Match(pat, p); err == nil && ok {
				return true
			}
			// Also try matching just the base name for convenience.
			if ok, err := path.Match(pat, filepath.Base(p)); err == nil && ok {
				return true
			}
			continue
		}
		if strings.Contains(p, pat) {
			return true
		}
	}
	return false
}

// capPath bounds the stored path (hostile filenames can be arbitrary bytes).
func capPath(p string) string {
	if len(p) > maxPathBytes {
		return p[:maxPathBytes]
	}
	return p
}
