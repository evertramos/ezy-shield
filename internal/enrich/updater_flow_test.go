package enrich

// Coverage for the updater ORCHESTRATION (issue #361): download → atomic
// install → hot reload, and Run's immediate-download-when-missing contract.
// The extraction and secret-redaction layers already had focused tests; the
// flow that wires them together was at 0%.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mmdbServer serves a valid tar.gz (one .mmdb entry) for any edition and
// records the query parameters of each request.
func mmdbServer(t *testing.T, body []byte) (*httptest.Server, *atomic.Int32, chan string) {
	t.Helper()
	var hits atomic.Int32
	editions := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		editions <- r.URL.Query().Get("edition_id")
		if r.URL.Query().Get("license_key") == "" {
			t.Error("download request missing license_key parameter")
		}
		tgz := makeTarGz(t, r.URL.Query().Get("edition_id")+".mmdb", body)
		_, _ = io.Copy(w, tgz)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits, editions
}

func TestUpdate_DownloadsBothEditionsInstallsAndReloads(t *testing.T) {
	t.Parallel()
	body := []byte("fake-mmdb-bytes")
	srv, hits, editions := mmdbServer(t, body)

	dir := t.TempDir()
	countryPath := filepath.Join(dir, "GeoLite2-Country.mmdb")
	asnPath := filepath.Join(dir, "GeoLite2-ASN.mmdb")

	u := NewUpdater(New(countryPath, asnPath), "test-license-key", countryPath, asnPath)
	u.baseURL = srv.URL

	if err := u.update(context.Background()); err != nil {
		t.Fatalf("update: %v", err)
	}

	for _, p := range []string{countryPath, asnPath} {
		got, err := os.ReadFile(p) //nolint:gosec // test-controlled temp path
		if err != nil {
			t.Fatalf("installed DB missing at %s: %v", p, err)
		}
		if string(got) != string(body) {
			t.Errorf("installed DB content mismatch at %s", p)
		}
	}
	if hits.Load() != 2 {
		t.Errorf("expected 2 downloads (Country+ASN), got %d", hits.Load())
	}
	want := map[string]bool{"GeoLite2-Country": false, "GeoLite2-ASN": false}
	for range 2 {
		want[<-editions] = true
	}
	for ed, seen := range want {
		if !seen {
			t.Errorf("edition %s never requested", ed)
		}
	}
	// Reload ran against the fresh files — invalid mmdb content must degrade
	// gracefully (enrichment disabled), never panic; nothing to assert beyond
	// having gotten here with update() == nil.
}

func TestUpdate_HTTPFailureNamesEditionNotKey(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	u := NewUpdater(New(filepath.Join(dir, "c.mmdb"), filepath.Join(dir, "a.mmdb")),
		"super-secret-license", filepath.Join(dir, "c.mmdb"), filepath.Join(dir, "a.mmdb"))
	u.baseURL = srv.URL

	err := u.update(context.Background())
	if err == nil {
		t.Fatal("403 download must fail update")
	}
	if !contains(err.Error(), "GeoLite2-Country") || !contains(err.Error(), "403") {
		t.Errorf("error should name the edition and status: %v", err)
	}
	if contains(err.Error(), "super-secret-license") {
		t.Fatalf("license key leaked into error: %v", err)
	}
}

// TestRun_DownloadsImmediatelyWhenDBsMissing pins Run's startup contract: a
// missing DB file triggers an immediate download before the weekly tick.
func TestRun_DownloadsImmediatelyWhenDBsMissing(t *testing.T) {
	t.Parallel()
	body := []byte("mmdb")
	srv, hits, _ := mmdbServer(t, body)

	dir := t.TempDir()
	countryPath := filepath.Join(dir, "country.mmdb")
	asnPath := filepath.Join(dir, "asn.mmdb")
	u := NewUpdater(New(countryPath, asnPath), "k", countryPath, asnPath)
	u.baseURL = srv.URL

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()

	deadline := time.After(5 * time.Second)
	for hits.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("Run never performed the immediate download for missing DBs")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}

	if !fileExists(countryPath) || !fileExists(asnPath) {
		t.Error("DB files not installed by the immediate download")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
