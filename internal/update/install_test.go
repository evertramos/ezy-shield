package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// stubDownloader implements Downloader from a static payload map keyed by URL.
type stubDownloader struct {
	payloads map[string][]byte
	calls    []string
}

func (s *stubDownloader) Download(_ context.Context, u string, dst io.Writer) (int64, error) {
	s.calls = append(s.calls, u)
	b, ok := s.payloads[u]
	if !ok {
		return 0, errors.New("no payload for " + u)
	}
	n, err := dst.Write(b)
	return int64(n), err
}

func TestDownloadVerified_OK(t *testing.T) {
	t.Parallel()
	body := []byte("hello binary")
	sum := sha256.Sum256(body)
	hexSum := hex.EncodeToString(sum[:])

	dir := t.TempDir()
	spec := AssetSpec{
		Name:        "asset",
		URL:         "https://example.test/asset",
		WantSHA256:  hexSum,
		InstallPath: filepath.Join(dir, "asset"),
	}
	dl := &stubDownloader{payloads: map[string][]byte{spec.URL: body}}

	tmp, err := DownloadVerified(context.Background(), dl, spec)
	if err != nil {
		t.Fatalf("DownloadVerified: %v", err)
	}
	if filepath.Dir(tmp) != dir {
		t.Errorf("temp file %q not sibling of install path", tmp)
	}
	got, err := os.ReadFile(tmp) //nolint:gosec // tmp is under t.TempDir()
	if err != nil {
		t.Fatalf("read tmp: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Error("tmp file content mismatch")
	}
}

func TestDownloadVerified_BadSHA(t *testing.T) {
	t.Parallel()
	body := []byte("hello binary")
	dir := t.TempDir()
	spec := AssetSpec{
		Name:        "asset",
		URL:         "https://example.test/asset",
		WantSHA256:  "0000000000000000000000000000000000000000000000000000000000000000",
		InstallPath: filepath.Join(dir, "asset"),
	}
	dl := &stubDownloader{payloads: map[string][]byte{spec.URL: body}}

	_, err := DownloadVerified(context.Background(), dl, spec)
	if err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
	// Temp file must be removed on mismatch — never leave a corrupt binary on disk.
	// Scan the directory: no .ezyupdate.*.tmp files should remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file not cleaned up after checksum mismatch: %s", e.Name())
		}
	}
}

func TestDownloadVerified_MissingSHA(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	spec := AssetSpec{
		Name:        "asset",
		URL:         "https://example.test/asset",
		WantSHA256:  "",
		InstallPath: filepath.Join(dir, "asset"),
	}
	if _, err := DownloadVerified(context.Background(), &stubDownloader{}, spec); err == nil {
		t.Error("expected error for missing want SHA")
	}
}

func TestDownloadVerified_ContextCancelled(t *testing.T) {
	t.Parallel()
	body := []byte("hello binary")
	sum := sha256.Sum256(body)
	hexSum := hex.EncodeToString(sum[:])

	dir := t.TempDir()
	spec := AssetSpec{
		Name:        "asset",
		URL:         "https://example.test/asset",
		WantSHA256:  hexSum,
		InstallPath: filepath.Join(dir, "asset"),
	}
	dl := &stubDownloader{payloads: map[string][]byte{spec.URL: body}}

	// Cancel BEFORE calling; the stub downloader doesn't honor ctx, so this
	// exercises the post-Download ctx.Err() guard.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DownloadVerified(ctx, dl, spec)
	if err == nil {
		t.Fatal("expected cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error not wrapping context.Canceled: %v", err)
	}
	// Cancelled run must not leave a temp file behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file not cleaned up after cancellation: %s", e.Name())
		}
	}
}

func TestAtomicReplace(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tmp := filepath.Join(dir, ".target.ezyupdate.tmp")
	final := filepath.Join(dir, "target")

	// Pre-existing "old" binary at final path.
	if err := os.WriteFile(final, []byte("OLD"), 0o600); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, []byte("NEW"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := AtomicReplace(tmp, final, 0o755); err != nil {
		t.Fatalf("AtomicReplace: %v", err)
	}
	got, err := os.ReadFile(final) //nolint:gosec // final is a t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "NEW" {
		t.Errorf("final content = %q, want NEW", got)
	}
	info, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("final mode = %o, want 0755", info.Mode().Perm())
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("tmp not consumed by rename: %v", err)
	}
}
