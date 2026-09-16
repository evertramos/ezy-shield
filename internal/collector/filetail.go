// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

// Package collector provides log collectors that implement sdk.Collector.
package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// inotifyEventSize is the fixed part of an inotify_event struct.
// The name field (variable length) follows immediately after.
const inotifyEventSize = int(unsafe.Sizeof(unix.InotifyEvent{}))

// pollTimeout is how often Poll is re-checked so context cancellation is honoured.
const pollTimeout = 500 // milliseconds

// fileWatchMask is the inotify mask installed on the tailed file.
const fileWatchMask = unix.IN_MODIFY | unix.IN_MOVE_SELF | unix.IN_DELETE_SELF

// inotifyAddWatch is the watch installer; tests swap it to inject failures
// on the re-watch path (issue #634).
var inotifyAddWatch = unix.InotifyAddWatch

// FileTailCollector tails a file using Linux inotify, handling log rotation.
// It seeks to EOF on startup (tail -f behaviour) and emits each complete line
// as an sdk.RawLine on the out channel.
type FileTailCollector struct {
	// Path is the absolute path of the file to tail.
	Path string
	// Logger receives debug/warn messages; if nil a no-op logger is used.
	Logger *slog.Logger
	// SourceOverride, when non-empty, replaces "file:<Path>" as the Source
	// field in emitted RawLines. Set by buildCollectors when the config has
	// a 'parser' field, so parser Matches() can route by prefix (e.g. "nginx:<path>").
	SourceOverride string
}

// Name returns a stable identity for supervision logs/alerts (issue #305).
func (c *FileTailCollector) Name() string { return "filetail:" + c.Path }

// Run starts tailing the file and writes sdk.RawLine values to out until ctx
// is cancelled or a fatal error occurs.  It returns nil on clean shutdown and
// a wrapped error on failure.
func (c *FileTailCollector) Run(ctx context.Context, out chan<- sdk.RawLine) error {
	logger := c.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Open the file; if it doesn't exist, return an error (caller retries).
	f, err := os.Open(c.Path)
	if err != nil {
		return fmt.Errorf("filetail: open %s: %w", c.Path, err)
	}

	// Seek to end so we don't replay historical content.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return fmt.Errorf("filetail: seek %s: %w", c.Path, err)
	}

	// Initialise inotify.
	ifd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("filetail: inotify_init1: %w", err)
	}
	defer func() { _ = unix.Close(ifd) }()

	// Watch the file for modifications and renames/deletes.
	fileWd, err := inotifyAddWatch(ifd, c.Path, fileWatchMask)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("filetail: inotify_add_watch file: %w", err)
	}

	// Watch the parent directory to detect rotation (rename + recreate / new file).
	dir := filepath.Dir(c.Path)
	dirWd, err := unix.InotifyAddWatch(ifd, dir, unix.IN_CREATE|unix.IN_MOVED_TO)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("filetail: inotify_add_watch dir: %w", err)
	}

	_ = dirWd // directory events are not dispatched; the watch keeps the dir alive for rotation

	source := "file:" + c.Path
	if c.SourceOverride != "" {
		source = c.SourceOverride
	}
	asm := newLineAssembler(maxStreamLineBytes) // capped partial-line accumulator (issue #307)
	ibuf := make([]byte, 4096+256*16)           // inotify read buffer (multiple events)

	pollFds := []unix.PollFd{
		{Fd: int32(ifd), Events: unix.POLLIN}, //nolint:gosec // ifd is a valid non-negative fd from InotifyInit1
	}

	rotated := false // set when we see IN_MOVE_SELF / IN_DELETE_SELF on the CURRENT watch

	// Truncation and growth are judged against the descriptor's own read
	// offset, never against a size sampled earlier (issue #634): a
	// copytruncate landing while drainLines was blocked on out, or in the
	// gap between the drain and its stat, left a stale "last size" that hid
	// the truncation until the file regrew past the offset.
	readOffset := func() int64 {
		pos, seekErr := f.Seek(0, io.SeekCurrent)
		if seekErr != nil {
			return 0
		}
		return pos
	}

	// rewindIfTruncated checks for copytruncate BEFORE any read: if the file
	// is now shorter than our offset, the writer truncated it in place and
	// the offset points past EOF. Seek to 0 and drop any partial line.
	rewindIfTruncated := func() {
		fi, statErr := f.Stat()
		if statErr != nil {
			return
		}
		if fi.Size() < readOffset() {
			_, _ = f.Seek(0, io.SeekStart)
			asm.discard()
		}
	}

	// followRotation switches to the file now at c.Path after the watched
	// inode was renamed or deleted (the caller has drained the old one).
	// A failed re-watch is not fatal: the timeout branch keeps retrying it
	// and, until it succeeds, detects the next rename by inode.
	followRotation := func() error {
		_ = f.Close()
		if fileWd >= 0 {
			// Drop the watch on the old inode so its later deletion is
			// never reported (and the wd is not leaked per rotation).
			_, _ = unix.InotifyRmWatch(ifd, uint32(fileWd)) //nolint:gosec // wd is a small non-negative watch descriptor
		}
		// Wait briefly for the new file to appear.
		newF, openErr := reopenWithRetry(ctx, c.Path, 5, 100*time.Millisecond)
		if openErr != nil {
			return fmt.Errorf("filetail: reopen after rotation: %w", openErr)
		}
		f = newF
		asm.discard()
		// Watch the new inode; events are dispatched by this wd.
		newWd, addErr := inotifyAddWatch(ifd, c.Path, fileWatchMask)
		if addErr != nil {
			logger.Warn("filetail: re-watch after rotation failed; polling the path until the watch is restored",
				slog.String("path", c.Path), slog.String("err", addErr.Error()))
			fileWd = -1
		} else {
			fileWd = newWd
		}
		return nil
	}

	for {
		// Check context before blocking.
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil
		default:
		}

		// Poll with timeout so we check ctx periodically.
		n, err := unix.Poll(pollFds, pollTimeout)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			_ = f.Close()
			return fmt.Errorf("filetail: poll: %w", err)
		}

		if n == 0 {
			// Timeout — no inotify event. Apply stat-based fallback so that
			// growth is caught even when Poll does not surface the inotify fd
			// as readable (observed on Debian 12 amd64, overlay2 filesystem).
			if fileWd < 0 {
				// No watch on the current inode: fstat alone can never see a
				// rename, so compare the path's inode with ours first, then
				// try to restore the watch (issue #634).
				if pathRotated(f, c.Path) {
					if drainErr := drainLines(ctx, f, asm, source, out, logger); drainErr != nil {
						logger.Debug("filetail: drain before rotation", slog.String("err", drainErr.Error()))
					}
					if err := followRotation(); err != nil {
						return err
					}
					continue
				}
				if wd, addErr := inotifyAddWatch(ifd, c.Path, fileWatchMask); addErr == nil {
					fileWd = wd
				}
			}
			rewindIfTruncated()
			if fi, statErr := f.Stat(); statErr == nil && fi.Size() > readOffset() {
				if err := drainLines(ctx, f, asm, source, out, logger); err != nil {
					logger.Debug("filetail: stat-fallback drain", slog.String("err", err.Error()))
				}
			}
			continue
		}

		if pollFds[0].Revents&unix.POLLIN != 0 {
			// Read all pending inotify events.
			nr, err := unix.Read(ifd, ibuf)
			if err != nil && err != unix.EAGAIN {
				_ = f.Close()
				return fmt.Errorf("filetail: read inotify: %w", err)
			}

			// copytruncate emits IN_MODIFY, so this branch sees the
			// truncation first: rewind BEFORE draining, or the read at the
			// stale offset returns EOF and the truncation stays hidden
			// until the file regrows past it (issue #611).
			rewindIfTruncated()

			// Drain any pending data first.
			err = drainLines(ctx, f, asm, source, out, logger)
			if err != nil {
				logger.Debug("filetail: drain error", slog.String("err", err.Error()))
			}

			// Parse each inotify event. Mask drives rotation detection, Len
			// skips the trailing name field, and Wd tells which watch the
			// event belongs to: after a rotation the OLD inode keeps its
			// watch until it is removed below, and a later IN_DELETE_SELF on
			// it (logrotate compress, Docker max-file pruning) must not be
			// mistaken for a rotation of the CURRENT file — that reopened
			// the live file at offset 0 and replayed it (issue #611).
			for offset := 0; offset+inotifyEventSize <= nr; {
				evBytes := ibuf[offset : offset+inotifyEventSize]
				wd := int(int32(binary.NativeEndian.Uint32(evBytes[0:4]))) //nolint:gosec // inotify wd is a small non-negative int32
				mask := binary.NativeEndian.Uint32(evBytes[4:8])
				evLen := binary.NativeEndian.Uint32(evBytes[12:16])
				offset += inotifyEventSize + int(evLen)

				if wd != fileWd {
					continue // directory watch, or a stale watch on a rotated inode
				}
				if mask&(unix.IN_MOVE_SELF|unix.IN_DELETE_SELF) != 0 {
					rotated = true
				}
			}

			// If the file was rotated, reopen after draining.
			if rotated {
				rotated = false
				if err := followRotation(); err != nil {
					return err
				}
			}
		}
	}
}

// pathRotated reports whether path now names a different inode than the
// open descriptor f — the rename/recreate shape of logrotate — or has been
// removed. Used only while no inotify watch is installed (issue #634).
func pathRotated(f *os.File, path string) bool {
	cur, err := f.Stat()
	if err != nil {
		return false
	}
	now, err := os.Stat(path)
	if err != nil {
		return false // renamed away and not recreated yet: keep the old inode until it is
	}
	return !os.SameFile(cur, now)
}

// drainLines reads all available data from f, splits on newlines via the
// capped assembler, and sends complete lines to out. Partial trailing data
// stays buffered in asm — bounded at maxStreamLineBytes, so a newline-less
// writer can no longer grow the accumulator without limit (issue #307).
func drainLines(ctx context.Context, f *os.File, asm *lineAssembler, source string, out chan<- sdk.RawLine, logger *slog.Logger) error {
	tmp := make([]byte, 4096)
	for {
		n, err := f.Read(tmp)
		if n > 0 {
			stopped := asm.feed(tmp[:n], func(line []byte) bool {
				cp := make([]byte, len(line))
				copy(cp, line)
				// Send races cancellation (issue #358): after the pipeline
				// stops reading, a plain blocking send would wedge the
				// collector goroutine forever during shutdown. The
				// non-blocking attempt runs FIRST so a graceful SIGTERM
				// drain (ctx done, pipeline still consuming) never randomly
				// drops deliverable lines to the select's uniform choice.
				rl := sdk.RawLine{Source: source, Line: cp, At: time.Now()}
				select {
				case out <- rl:
					return false
				default:
				}
				select {
				case out <- rl:
					return false
				case <-ctx.Done():
					return true
				}
			})
			if stopped {
				return ctx.Err()
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Debug("filetail: read error", slog.String("err", err.Error()))
			return fmt.Errorf("drainLines: %w", err)
		}
	}
	return nil
}

// reopenWithRetry attempts to open path up to maxTries times, waiting wait
// between each attempt, honouring ctx cancellation.
func reopenWithRetry(ctx context.Context, path string, maxTries int, wait time.Duration) (*os.File, error) {
	for i := 0; i < maxTries; i++ {
		f, err := os.Open(path) //nolint:gosec // path comes from FileTailCollector.Path, set by the operator, not attacker-controlled
		if err == nil {
			return f, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, fmt.Errorf("reopenWithRetry: file %s did not reappear after %d tries", path, maxTries)
}
