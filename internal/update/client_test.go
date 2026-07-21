package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeRelease constructs a minimal GitHub Releases JSON payload.
func fakeRelease(tag, assetBaseURL string) Release {
	return Release{
		TagName: tag,
		Assets: []Asset{
			{Name: "ezyshield-linux-amd64", URL: assetBaseURL + "/ezyshield-linux-amd64"},
			{Name: "ezyshield-linux-arm64", URL: assetBaseURL + "/ezyshield-linux-arm64"},
			{Name: "ezyshield-enforcer-linux-amd64", URL: assetBaseURL + "/ezyshield-enforcer-linux-amd64"},
			{Name: "checksums.txt", URL: assetBaseURL + "/checksums.txt"},
		},
	}
}

// httpsTestServer returns an httptest.NewTLSServer wired with the handler,
// plus a Client whose APIBaseURL points at it and whose HTTP client trusts the
// server's self-signed cert.
func httpsTestServer(t *testing.T, h http.Handler) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	c := NewClient()
	c.HTTP = srv.Client()
	c.HTTP.Timeout = 5 * time.Second
	c.APIBaseURL = srv.URL
	c.Repo = "test/repo"
	return srv, c
}

func TestClient_LatestRelease(t *testing.T) {
	t.Parallel()
	var assetBase string
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/test/repo/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		rel := fakeRelease("v0.2.0", assetBase)
		_ = json.NewEncoder(w).Encode(rel)
	})
	srv, c := httpsTestServer(t, mux)
	assetBase = srv.URL + "/dl"

	rel, err := c.LatestRelease(context.Background())
	if err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	if rel.TagName != "v0.2.0" {
		t.Errorf("TagName = %q, want v0.2.0", rel.TagName)
	}
	if _, ok := rel.FindAsset("ezyshield-linux-amd64"); !ok {
		t.Error("expected linux-amd64 asset in release")
	}
}

// TestClient_LatestRelease_NoStableYet reproduces issue #235: before any
// stable tag exists, GitHub's /releases/latest 404s. LatestRelease must
// translate that into the named ErrNoStableRelease, not a bare "not found".
func TestClient_LatestRelease_NoStableYet(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/test/repo/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	})
	_, c := httpsTestServer(t, mux)

	_, err := c.LatestRelease(context.Background())
	if !errors.Is(err, ErrNoStableRelease) {
		t.Fatalf("LatestRelease error = %v, want errors.Is(err, ErrNoStableRelease)", err)
	}
}

// TestClient_ReleaseByTag_NotFoundIsNotConfusedWithNoStableRelease guards
// against the sentinel leaking into the wrong context: a bad/nonexistent
// tag on ReleaseByTag is a different condition (typo, deleted release) and
// must NOT be mistaken for "no stable release published yet".
func TestClient_ReleaseByTag_NotFoundIsNotConfusedWithNoStableRelease(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/test/repo/releases/tags/v9.9.9", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	})
	_, c := httpsTestServer(t, mux)

	_, err := c.ReleaseByTag(context.Background(), "v9.9.9")
	if err == nil {
		t.Fatal("want error for nonexistent tag")
	}
	if errors.Is(err, ErrNoStableRelease) {
		t.Errorf("ReleaseByTag 404 must not be classified as ErrNoStableRelease: %v", err)
	}
	if !strings.Contains(err.Error(), "release not found") {
		t.Errorf("expected a release-not-found style message, got %v", err)
	}
}

func TestClient_NewestRelease(t *testing.T) {
	t.Parallel()
	var assetBase string
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/test/repo/releases", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("per_page"); got != "1" {
			t.Errorf("per_page = %q, want 1", got)
		}
		_ = json.NewEncoder(w).Encode([]Release{
			fakeRelease("v0.1.0-rc.21", assetBase),
			fakeRelease("v0.1.0-rc.20", assetBase),
		})
	})
	srv, c := httpsTestServer(t, mux)
	assetBase = srv.URL + "/dl"

	rel, err := c.NewestRelease(context.Background())
	if err != nil {
		t.Fatalf("NewestRelease: %v", err)
	}
	if rel.TagName != "v0.1.0-rc.21" {
		t.Errorf("TagName = %q, want the first (newest) entry v0.1.0-rc.21", rel.TagName)
	}
}

func TestClient_NewestRelease_EmptyList(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/test/repo/releases", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]Release{})
	})
	_, c := httpsTestServer(t, mux)

	if _, err := c.NewestRelease(context.Background()); err == nil {
		t.Error("NewestRelease with zero releases published should error")
	}
}

func TestClient_ReleaseByTag_RejectsBadTag(t *testing.T) {
	t.Parallel()
	c := NewClient()
	c.APIBaseURL = "https://example.com"
	bad := []string{"../etc", "v1.2", "1.2.3/4", "v1.2.3 something", ""}
	for _, tag := range bad {
		if _, err := c.ReleaseByTag(context.Background(), tag); err == nil {
			t.Errorf("ReleaseByTag(%q): expected error, got nil", tag)
		}
	}
}

func TestClient_RejectsHTTP(t *testing.T) {
	t.Parallel()
	c := NewClient()
	c.APIBaseURL = "http://api.example.com" // plain HTTP

	if _, err := c.LatestRelease(context.Background()); err == nil {
		t.Error("LatestRelease against http:// URL should fail")
	}
	var buf bytes.Buffer
	if _, err := c.Download(context.Background(), "http://example.com/x", &buf); err == nil {
		t.Error("Download against http:// URL should fail")
	}
}

func TestClient_Download(t *testing.T) {
	t.Parallel()
	want := []byte("fake binary payload")
	mux := http.NewServeMux()
	mux.HandleFunc("/dl/file.bin", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(want)
	})
	srv, c := httpsTestServer(t, mux)

	var got bytes.Buffer
	n, err := c.Download(context.Background(), srv.URL+"/dl/file.bin", &got)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if n != int64(len(want)) {
		t.Errorf("got %d bytes, want %d", n, len(want))
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("body mismatch")
	}
}

func TestClient_Download_404(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/missing", func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	srv, c := httpsTestServer(t, mux)

	var buf bytes.Buffer
	if _, err := c.Download(context.Background(), srv.URL+"/missing", &buf); err == nil {
		t.Error("Download 404 should error")
	}
}

func TestClient_DownloadChecksums(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	h := sha256.Sum256([]byte("payload"))
	hexSum := hex.EncodeToString(h[:])
	body := hexSum + "  ezyshield-linux-amd64\n"
	mux.HandleFunc("/dl/checksums.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	srv, c := httpsTestServer(t, mux)

	sums, err := c.DownloadChecksums(context.Background(), srv.URL+"/dl/checksums.txt")
	if err != nil {
		t.Fatalf("DownloadChecksums: %v", err)
	}
	if sums["ezyshield-linux-amd64"] != hexSum {
		t.Errorf("got %q, want %q", sums["ezyshield-linux-amd64"], hexSum)
	}
}

func TestRedactURL(t *testing.T) {
	t.Parallel()
	const sentinel = "tk-redacted-test-value" //nolint:gosec // test sentinel, not a real credential
	in := "https://example.com/x?token=" + sentinel + "#frag"
	got := redactURL(in)
	if strings.Contains(got, sentinel) {
		t.Errorf("token leaked: %q", got)
	}
	if got != "https://example.com/x" {
		t.Errorf("redactURL = %q, want https://example.com/x", got)
	}
	// Re-parse to confirm result is a valid URL.
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if u.RawQuery != "" {
		t.Errorf("query not stripped: %q", u.RawQuery)
	}
}
