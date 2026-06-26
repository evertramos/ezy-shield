//go:build linux

// Package collector provides log collectors that implement sdk.Collector.
package collector

import (
	"bytes"
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
	fileWd, err := unix.InotifyAddWatch(ifd, c.Path,
		unix.IN_MODIFY|unix.IN_MOVE_SELF|unix.IN_DELETE_SELF)
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

	// Suppress "declared and not used" if wd vars are only used in event handling.
	_ = fileWd
	_ = dirWd

	source := "file:" + c.Path
	if c.SourceOverride != "" {
		source = c.SourceOverride
	}
	buf := make([]byte, 0, 4096)      // partial-line accumulator
	ibuf := make([]byte, 4096+256*16) // inotify read buffer (multiple events)

	pollFds := []unix.PollFd{
		{Fd: int32(ifd), Events: unix.POLLIN}, //nolint:gosec // ifd is a valid non-negative fd from InotifyInit1
	}

	rotated := false // set when we see IN_MOVE_SELF / IN_DELETE_SELF

	// lastSize tracks the file size seen at the previous iteration for the
	// stat-based fallback that fires when inotify events are not delivered to
	// Poll (reproducible on Debian 12 kernel 6.1 with overlay2 storage).
	var lastSize int64
	if fi, statErr := f.Stat(); statErr == nil {
		lastSize = fi.Size()
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
			if fi, statErr := f.Stat(); statErr == nil {
				if fi.Size() < lastSize {
					// copytruncate: file was truncated in-place (logrotate).
					// Seek to start so new content is not skipped, and discard
					// any partial line from the old file that's still in buf.
					_, _ = f.Seek(0, io.SeekStart)
					lastSize = 0
					buf = buf[:0]
				}
				if fi.Size() > lastSize {
					buf, err = drainLines(f, buf, source, out, logger)
					if err != nil {
						logger.Debug("filetail: stat-fallback drain", slog.String("err", err.Error()))
					}
					if fi2, statErr2 := f.Stat(); statErr2 == nil {
						lastSize = fi2.Size()
					}
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

			// Drain any pending data first.
			buf, err = drainLines(f, buf, source, out, logger)
			if err != nil {
				logger.Debug("filetail: drain error", slog.String("err", err.Error()))
			}
			if fi, statErr := f.Stat(); statErr == nil {
				lastSize = fi.Size()
			}

			// Parse each inotify event.
			for offset := 0; offset+inotifyEventSize <= nr; {
				var ev unix.InotifyEvent
				// Use binary.NativeEndian (no unsafe) per the spec.
				evBytes := ibuf[offset : offset+inotifyEventSize]
				ev.Wd = int32(binary.NativeEndian.Uint32(evBytes[0:4])) //nolint:gosec // inotify Wd is a kernel-assigned watch descriptor; the int32↔uint32 round-trip is intentional
				ev.Mask = binary.NativeEndian.Uint32(evBytes[4:8])
				ev.Cookie = binary.NativeEndian.Uint32(evBytes[8:12])
				ev.Len = binary.NativeEndian.Uint32(evBytes[12:16])
				offset += inotifyEventSize + int(ev.Len)

				if ev.Mask&(unix.IN_MOVE_SELF|unix.IN_DELETE_SELF) != 0 {
					rotated = true
				}
			}

			// If the file was rotated, reopen after draining.
			if rotated {
				rotated = false
				_ = f.Close()

				// Wait briefly for the new file to appear.
				newF, openErr := reopenWithRetry(ctx, c.Path, 5, 100*time.Millisecond)
				if openErr != nil {
					return fmt.Errorf("filetail: reopen after rotation: %w", openErr)
				}
				f = newF
				buf = buf[:0]

				// Update inotify watch to the new file.
				_, _ = unix.InotifyAddWatch(ifd, c.Path,
					unix.IN_MODIFY|unix.IN_MOVE_SELF|unix.IN_DELETE_SELF)
			}
		}
	}
}

// drainLines reads all available data from f, splits on newlines, and sends
// complete lines to out. Partial trailing data is kept in buf.
func drainLines(f *os.File, buf []byte, source string, out chan<- sdk.RawLine, logger *slog.Logger) ([]byte, error) {
	tmp := make([]byte, 4096)
	for {
		n, err := f.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				idx := bytes.IndexByte(buf, '\n')
				if idx < 0 {
					break
				}
				line := make([]byte, idx)
				copy(line, buf[:idx])
				out <- sdk.RawLine{
					Source: source,
					Line:   line,
					At:     time.Now(),
				}
				buf = buf[idx+1:]
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Debug("filetail: read error", slog.String("err", err.Error()))
			return buf, fmt.Errorf("drainLines: %w", err)
		}
	}
	return buf, nil
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
