package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// AssetSpec describes a single binary asset to download, verify, and install.
type AssetSpec struct {
	Name        string // asset name in checksums.txt (e.g. "ezyshield-linux-amd64")
	URL         string // direct HTTPS download URL
	WantSHA256  string // lower-case hex digest from checksums.txt
	InstallPath string // final on-disk path (atomic destination)
}

// Downloader is the slice of *Client that DownloadVerified needs.
type Downloader interface {
	Download(ctx context.Context, url string, dst io.Writer) (int64, error)
}

// DownloadVerified streams spec.URL into a fresh temp file beside
// spec.InstallPath while computing SHA256, then verifies the digest matches
// spec.WantSHA256. Returns the temp file path so the caller can hand it to
// AtomicReplace. On any error the temp file is removed.
//
// The temp file is created with os.CreateTemp, which uses a random suffix and
// opens with O_CREATE|O_EXCL — so an attacker can't pre-create a symlink at a
// predictable path and trick us into writing through it. The temp lives in
// filepath.Dir(spec.InstallPath) so the subsequent os.Rename is atomic
// (same filesystem).
func DownloadVerified(ctx context.Context, client Downloader, spec AssetSpec) (string, error) {
	if spec.WantSHA256 == "" {
		return "", fmt.Errorf("download %s: missing expected sha256", spec.Name)
	}
	dir := filepath.Dir(spec.InstallPath)
	base := filepath.Base(spec.InstallPath)
	f, err := os.CreateTemp(dir, "."+base+".ezyupdate.*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpPath := f.Name()
	cleanup := true
	defer func() {
		_ = f.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	mw := io.MultiWriter(f, hasher)
	if _, err := client.Download(ctx, spec.URL, mw); err != nil {
		return "", fmt.Errorf("download %s: %w", spec.Name, err)
	}
	// io.Copy inside Download doesn't observe ctx cancellation between reads, so
	// re-check before we commit bytes to disk or claim the digest matches.
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("download %s cancelled: %w", spec.Name, err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("sync %s: %w", tmpPath, err)
	}
	got := hex.EncodeToString(hasher.Sum(nil))
	if got != spec.WantSHA256 {
		return "", fmt.Errorf("checksum mismatch for %s: got %s, want %s",
			spec.Name, got, spec.WantSHA256)
	}
	cleanup = false
	return tmpPath, nil
}

// AtomicReplace chmods tmpPath to mode then renames it onto finalPath. The two
// paths must be on the same filesystem (DownloadVerified ensures this by
// placing the temp file in filepath.Dir(spec.InstallPath)). "Atomic" here is
// the POSIX rename(2) guarantee: finalPath always points at the old binary or
// the new one — never a half-written file.
func AtomicReplace(tmpPath, finalPath string, mode os.FileMode) error {
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, finalPath, err)
	}
	return nil
}
