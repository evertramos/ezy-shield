package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/update"
)

// fixture builds an httptest TLS server that mimics GitHub Releases for two
// linux-amd64 binaries (ezyshield + enforcer) plus checksums.txt.
type fixture struct {
	srv          *httptest.Server
	mainBytes    []byte
	enfBytes     []byte
	mainSHA      string
	enfSHA       string
	checksumBody string
	tag          string
}

func newFixture(t *testing.T, tag string) *fixture {
	t.Helper()
	f := &fixture{
		tag:       tag,
		mainBytes: []byte("FAKE_EZYSHIELD_BINARY_" + tag),
		enfBytes:  []byte("FAKE_ENFORCER_BINARY_" + tag),
	}
	ms := sha256.Sum256(f.mainBytes)
	es := sha256.Sum256(f.enfBytes)
	f.mainSHA = hex.EncodeToString(ms[:])
	f.enfSHA = hex.EncodeToString(es[:])
	f.checksumBody = f.mainSHA + "  ezyshield-linux-amd64\n" +
		f.enfSHA + "  ezyshield-enforcer-linux-amd64\n"

	mux := http.NewServeMux()
	// Asset endpoints registered first; release JSON references them via the
	// server's own URL (set after NewTLSServer below).
	mux.HandleFunc("/dl/ezyshield-linux-amd64", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(f.mainBytes)
	})
	mux.HandleFunc("/dl/ezyshield-enforcer-linux-amd64", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(f.enfBytes)
	})
	mux.HandleFunc("/dl/checksums.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(f.checksumBody))
	})

	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)

	// Register the release endpoints now that we know f.srv.URL.
	rel := update.Release{
		TagName: tag,
		Assets: []update.Asset{
			{Name: "ezyshield-linux-amd64", URL: f.srv.URL + "/dl/ezyshield-linux-amd64"},
			{Name: "ezyshield-enforcer-linux-amd64", URL: f.srv.URL + "/dl/ezyshield-enforcer-linux-amd64"},
			{Name: "checksums.txt", URL: f.srv.URL + "/dl/checksums.txt"},
		},
	}
	mux.HandleFunc("/repos/test/repo/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rel)
	})
	mux.HandleFunc("/repos/test/repo/releases/tags/"+tag, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rel)
	})

	return f
}

// optsFor builds updateOptions wired against the fixture, with --verify and
// --is-root stubbed to inject test behavior. Binary lives under tmpDir.
func (f *fixture) optsFor(t *testing.T, tmpDir string, current string) updateOptions {
	t.Helper()
	mainPath := filepath.Join(tmpDir, "ezyshield")
	enfPath := filepath.Join(tmpDir, "ezyshield-enforcer")
	// Seed old binaries so AtomicReplace has something to overwrite.
	if err := os.WriteFile(mainPath, []byte("OLD_MAIN"), 0o600); err != nil { //nolint:gosec // test fixture, real binaries get 0o755 via AtomicReplace
		t.Fatal(err)
	}
	if err := os.WriteFile(enfPath, []byte("OLD_ENF"), 0o600); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	return updateOptions{
		currentVersion: current,
		apiBaseURL:     f.srv.URL,
		repo:           "test/repo",
		binaryPath:     mainPath,
		enforcerPath:   enfPath,
		goos:           "linux",
		arch:           "amd64",
		runVerify:      func(_ context.Context, _ string) error { return nil },
		isRoot:         func() bool { return true },
		out:            &bytes.Buffer{},
	}
}

// withTestClient installs a newClientHook that returns an update.Client whose
// HTTP transport trusts the fixture's self-signed cert. Required because
// httptest.NewTLSServer uses a self-signed certificate.
func withTestClient(t *testing.T, f *fixture) {
	t.Helper()
	prev := newClientHook
	newClientHook = func() *update.Client {
		c := update.NewClient()
		c.HTTP = f.srv.Client()
		return c
	}
	t.Cleanup(func() { newClientHook = prev })
}

// TestRunUpdate_HappyPath drives runUpdate against the fixture: it must
// download checksums + both binaries, verify SHA256, exec --version (stubbed),
// then atomically replace both files.
func TestRunUpdate_HappyPath(t *testing.T) {
	f := newFixture(t, "v0.2.0")
	tmpDir := t.TempDir()
	opts := f.optsFor(t, tmpDir, "v0.1.0")
	buf := &bytes.Buffer{}
	opts.out = buf
	withTestClient(t, f)

	if err := runUpdate(context.Background(), opts); err != nil {
		t.Fatalf("runUpdate: %v\nout: %s", err, buf.String())
	}

	got, err := os.ReadFile(opts.binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, f.mainBytes) {
		t.Errorf("ezyshield not replaced; got %q", got)
	}
	got, err = os.ReadFile(opts.enforcerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, f.enfBytes) {
		t.Errorf("enforcer not replaced; got %q", got)
	}
	if !strings.Contains(buf.String(), "Updated: v0.1.0 → v0.2.0") {
		t.Errorf("missing summary line; output:\n%s", buf.String())
	}
}

func TestRunUpdate_AlreadyUpToDate(t *testing.T) {
	f := newFixture(t, "v0.2.0")
	tmpDir := t.TempDir()
	opts := f.optsFor(t, tmpDir, "v0.2.0")
	buf := &bytes.Buffer{}
	opts.out = buf
	withTestClient(t, f)

	if err := runUpdate(context.Background(), opts); err != nil {
		t.Fatalf("runUpdate: %v", err)
	}
	if !strings.Contains(buf.String(), "Already up to date") {
		t.Errorf("expected up-to-date message; got %q", buf.String())
	}
	// Binaries must NOT be modified.
	got, _ := os.ReadFile(opts.binaryPath)
	if string(got) != "OLD_MAIN" {
		t.Errorf("up-to-date should not rewrite binary; got %q", got)
	}
}

func TestRunUpdate_CheckOnly(t *testing.T) {
	f := newFixture(t, "v0.2.0")
	tmpDir := t.TempDir()
	opts := f.optsFor(t, tmpDir, "v0.1.0")
	opts.checkOnly = true
	buf := &bytes.Buffer{}
	opts.out = buf
	withTestClient(t, f)

	if err := runUpdate(context.Background(), opts); err != nil {
		t.Fatalf("runUpdate: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Current: v0.1.0") || !strings.Contains(out, "Latest:  v0.2.0") {
		t.Errorf("expected check summary; got %q", out)
	}
	got, _ := os.ReadFile(opts.binaryPath)
	if string(got) != "OLD_MAIN" {
		t.Errorf("--check must not rewrite binary; got %q", got)
	}
}

func TestRunUpdate_RequiresRoot(t *testing.T) {
	f := newFixture(t, "v0.2.0")
	tmpDir := t.TempDir()
	opts := f.optsFor(t, tmpDir, "v0.1.0")
	opts.isRoot = func() bool { return false }
	buf := &bytes.Buffer{}
	opts.out = buf
	withTestClient(t, f)

	err := runUpdate(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "requires root") {
		t.Errorf("expected requires-root error, got %v", err)
	}
}

func TestRunUpdate_PinnedVersion(t *testing.T) {
	f := newFixture(t, "v0.2.0")
	tmpDir := t.TempDir()
	opts := f.optsFor(t, tmpDir, "v0.5.0") // current is newer than target
	opts.pinnedVersion = "v0.2.0"          // force-downgrade
	buf := &bytes.Buffer{}
	opts.out = buf
	withTestClient(t, f)

	if err := runUpdate(context.Background(), opts); err != nil {
		t.Fatalf("runUpdate: %v\nout: %s", err, buf.String())
	}
	got, _ := os.ReadFile(opts.binaryPath)
	if !bytes.Equal(got, f.mainBytes) {
		t.Errorf("pinned downgrade should install target; got %q", got)
	}
}

func TestRunUpdate_ChecksumMismatch(t *testing.T) {
	f := newFixture(t, "v0.2.0")
	// Corrupt the served binary so its real digest no longer matches the
	// checksum line we publish.
	f.mainBytes = append(f.mainBytes, 'X')

	tmpDir := t.TempDir()
	opts := f.optsFor(t, tmpDir, "v0.1.0")
	buf := &bytes.Buffer{}
	opts.out = buf
	withTestClient(t, f)

	err := runUpdate(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("expected checksum mismatch error, got %v", err)
	}
	// Live binary must be untouched.
	got, _ := os.ReadFile(opts.binaryPath)
	if string(got) != "OLD_MAIN" {
		t.Errorf("checksum mismatch must not replace binary; got %q", got)
	}
}

func TestRunUpdate_NonLinuxFails(t *testing.T) {
	t.Parallel()
	opts := updateOptions{goos: "darwin", arch: "amd64", out: &bytes.Buffer{}}
	if err := runUpdate(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "Linux") {
		t.Errorf("expected Linux-only error, got %v", err)
	}
}

func TestRunUpdate_UnsupportedArch(t *testing.T) {
	t.Parallel()
	opts := updateOptions{goos: "linux", arch: "ppc64", out: &bytes.Buffer{}}
	if err := runUpdate(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "architecture") {
		t.Errorf("expected unsupported-arch error, got %v", err)
	}
}

func TestResolveUpdateSource(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in           string
		wantAPI      string
		wantRepo     string
		wantFallback bool
	}{
		{"", update.DefaultAPIBaseURL, update.DefaultRepo, false},
		{"https://mirror.example.com", "https://mirror.example.com", update.DefaultRepo, false},
		{"https://mirror.example.com/", "https://mirror.example.com", update.DefaultRepo, false},
		{"http://insecure.example", update.DefaultAPIBaseURL, update.DefaultRepo, true}, // HTTP → fallback
		{"not a url", update.DefaultAPIBaseURL, update.DefaultRepo, true},
	}
	for _, c := range cases {
		gotAPI, gotRepo := resolveUpdateSource(c.in)
		if gotAPI != c.wantAPI {
			t.Errorf("resolveUpdateSource(%q) api = %q, want %q", c.in, gotAPI, c.wantAPI)
		}
		if gotRepo != c.wantRepo {
			t.Errorf("resolveUpdateSource(%q) repo = %q, want %q", c.in, gotRepo, c.wantRepo)
		}
	}
}
