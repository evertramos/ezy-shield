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

func TestRunUpdate_TempBinaryIsExecutable(t *testing.T) {
	f := newFixture(t, "v0.2.0")
	tmpDir := t.TempDir()
	opts := f.optsFor(t, tmpDir, "v0.1.0")

	// Track whether verify was called and what permissions the file had at that time
	var permChecked bool
	var permAtCheck os.FileMode
	opts.runVerify = func(_ context.Context, path string) error {
		fi, err := os.Stat(path)
		if err != nil {
			return err
		}
		permChecked = true
		permAtCheck = fi.Mode()
		return nil
	}

	buf := &bytes.Buffer{}
	opts.out = buf
	withTestClient(t, f)

	if err := runUpdate(context.Background(), opts); err != nil {
		t.Fatalf("runUpdate: %v\nout: %s", err, buf.String())
	}

	if !permChecked {
		t.Fatal("verify callback was not called")
	}

	// Check that the file was executable (0755 mode includes owner execute bit 0o100)
	if permAtCheck&0o111 == 0 {
		t.Errorf("temp binary was not executable at verify time; mode was %o", permAtCheck)
	}
}

// TestRunUpdate_NoStableReleaseYet reproduces issue #235 end to end through
// runUpdate: GitHub's /releases/latest 404s (no stable tag exists), and the
// operator must see an actionable message — not the bare "release not
// found at ..." — naming the RC channel, a --version pin (resolved via the
// releases-list API), EZYSHIELD_UPDATE_URL, and that binaries are untouched.
func TestRunUpdate_NoStableReleaseYet(t *testing.T) {
	// No t.Parallel(): this test overrides the package-level newClientHook
	// (see withTestClient's doc comment) — the existing tests that touch
	// the same hook are sequential for the same reason; running two such
	// overrides in parallel is a data race on newClientHook itself, not a
	// flake (caught by -race in CI).
	var assetBase string
	mux := http.NewServeMux()
	// /releases/latest deliberately unregistered => 404, matching GitHub's
	// real behavior when only prereleases exist.
	mux.HandleFunc("/repos/test/repo/releases", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/test/repo/releases" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]update.Release{
			{TagName: "v0.1.0-rc.21", Assets: []update.Asset{
				{Name: "ezyshield-linux-amd64", URL: assetBase + "/ezyshield-linux-amd64"},
			}},
		})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	assetBase = srv.URL + "/dl"

	tmpDir := t.TempDir()
	mainPath := filepath.Join(tmpDir, "ezyshield")
	if err := os.WriteFile(mainPath, []byte("OLD_MAIN"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := updateOptions{
		currentVersion: "v0.1.0-rc.20",
		apiBaseURL:     srv.URL,
		repo:           "test/repo",
		binaryPath:     mainPath,
		enforcerPath:   filepath.Join(tmpDir, "ezyshield-enforcer"),
		goos:           "linux",
		arch:           "amd64",
		isRoot:         func() bool { return true },
		out:            &bytes.Buffer{},
	}
	prev := newClientHook
	newClientHook = func() *update.Client {
		c := update.NewClient()
		c.HTTP = srv.Client()
		return c
	}
	t.Cleanup(func() { newClientHook = prev })

	err := runUpdate(context.Background(), opts)
	if err == nil {
		t.Fatal("want an error — no stable release exists yet")
	}
	msg := err.Error()
	for _, want := range []string{
		"no stable release published yet",
		"--version v0.1.0-rc.21", // dynamically resolved via NewestRelease
		"EZYSHIELD_UPDATE_URL",
		"v0.1.0",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q; got:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "release not found at") {
		t.Errorf("message regressed to the bare not-found form: %s", msg)
	}
	got, _ := os.ReadFile(mainPath) //nolint:gosec // G304: test-owned temp path
	if string(got) != "OLD_MAIN" {
		t.Errorf("binary must not be touched; got %q", got)
	}
}

// TestRunUpdate_NoStableReleaseYet_NewestReleaseAlsoFails checks the
// degrade path: if the best-effort NewestRelease lookup itself fails, the
// message still names the condition and points at the releases page
// instead of erroring out entirely or omitting guidance.
func TestRunUpdate_NoStableReleaseYet_NewestReleaseAlsoFails(t *testing.T) {
	// No t.Parallel() — see the note in TestRunUpdate_NoStableReleaseYet:
	// this also overrides the shared newClientHook.
	mux := http.NewServeMux() // /releases/latest AND /releases both unregistered => both 404
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	opts := updateOptions{
		currentVersion: "v0.1.0-rc.20",
		apiBaseURL:     srv.URL,
		repo:           "test/repo",
		binaryPath:     filepath.Join(t.TempDir(), "ezyshield"),
		goos:           "linux",
		arch:           "amd64",
		isRoot:         func() bool { return true },
		out:            &bytes.Buffer{},
	}
	if err := os.WriteFile(opts.binaryPath, []byte("OLD"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := newClientHook
	newClientHook = func() *update.Client {
		c := update.NewClient()
		c.HTTP = srv.Client()
		return c
	}
	t.Cleanup(func() { newClientHook = prev })

	err := runUpdate(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "no stable release published yet") {
		t.Fatalf("want the actionable no-stable-release message even when NewestRelease fails, got %v", err)
	}
	if !strings.Contains(err.Error(), "test/repo/releases") {
		t.Errorf("degrade path should still point at the releases page: %v", err)
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
