// SPDX-License-Identifier: AGPL-3.0-only

// Package enrich — secret-leak gate tests (SECURITY-REVIEW §4, Hard Rule 3).
//
// Issue #294: the MaxMind license key is carried in the download URL's
// license_key query parameter. http.Client.Do always returns *url.Error, whose
// Error() embeds the full request URL — so any network failure (timeout, DNS,
// TLS, connection refused), guaranteed on air-gapped or flaky hosts, would
// otherwise write the credential to the journal via slog. These tests force
// each error path and assert the key never appears in the returned error chain.
// They are a mandatory CI gate mirroring internal/notify/secret_leak_test.go —
// do not delete.
package enrich

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// Fixture-only secret — clearly fake, never a real credential (Hard Rule 3).
const leakLicenseKey = "FAKE-MAXMIND-LICENSE-KEY-abc123def456"

// closedLoopbackURL returns an http URL on 127.0.0.1 with a port that was just
// released, so every request fails with a transport-level *url.Error
// (connection refused) without any network I/O leaving the host.
func closedLoopbackURL(t *testing.T, path string) string {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving closed port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr + path
}

func assertNoKey(t *testing.T, err error, key string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if strings.Contains(err.Error(), key) {
		t.Errorf("license key leaked into error string (Hard Rule 3 / §4):\n  %v", err)
	}
}

// TestSecretLeak_DownloadTransportError is the core reproduction of #294: a
// dial failure returns a *url.Error whose Error() embeds the full URL including
// license_key. The key must never survive into the wrapped error, and the raw
// query string must be gone.
func TestSecretLeak_DownloadTransportError(t *testing.T) {
	u := &Updater{
		licenseKey: leakLicenseKey,
		baseURL:    closedLoopbackURL(t, "/app/geoip_download"),
	}

	err := u.downloadEdition(context.Background(), "GeoLite2-Country",
		filepath.Join(t.TempDir(), "country.mmdb"))

	assertNoKey(t, err, leakLicenseKey)
	if strings.Contains(err.Error(), "license_key=") {
		t.Errorf("raw query string leaked into error (Hard Rule 3):\n  %v", err)
	}
	// The public host is kept for debuggability; the secret-bearing path/query
	// collapse to /[redacted].
	if !strings.Contains(err.Error(), "/[redacted]") {
		t.Errorf("expected redacted URL marker, got:\n  %v", err)
	}
}

// TestSecretLeak_DownloadBuildRequestError covers the http.NewRequestWithContext
// parse-error path. It is redacted defensively so it can never leak even if a
// future change moves the key into the parsed URL.
func TestSecretLeak_DownloadBuildRequestError(t *testing.T) {
	u := &Updater{
		licenseKey: leakLicenseKey,
		baseURL:    "http://%zz-invalid-url", // %zz is an invalid percent-escape
	}

	err := u.downloadEdition(context.Background(), "GeoLite2-Country",
		filepath.Join(t.TempDir(), "country.mmdb"))

	assertNoKey(t, err, leakLicenseKey)
}

// TestSecretLeak_DownloadNon2xx covers the non-2xx status path: the error is
// built from the status code and edition only, never the URL.
func TestSecretLeak_DownloadNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	u := &Updater{licenseKey: leakLicenseKey, baseURL: srv.URL}

	err := u.downloadEdition(context.Background(), "GeoLite2-Country",
		filepath.Join(t.TempDir(), "country.mmdb"))

	assertNoKey(t, err, leakLicenseKey)
}

// TestRedactURLErr_StripsQuery unit-tests the helper directly against a
// synthetic *url.Error carrying the key in the query, independent of transport.
func TestRedactURLErr_StripsQuery(t *testing.T) {
	raw := "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=" +
		leakLicenseKey + "&suffix=tar.gz"
	ue := &url.Error{Op: "Get", URL: raw, Err: errors.New("context deadline exceeded")}

	got := redactURLErr(ue).Error()
	if strings.Contains(got, leakLicenseKey) {
		t.Errorf("license key survived redaction:\n  %s", got)
	}
	if strings.Contains(got, "license_key=") {
		t.Errorf("raw query survived redaction:\n  %s", got)
	}
	if !strings.Contains(got, "https://download.maxmind.com/[redacted]") {
		t.Errorf("public host should be kept with redacted path, got:\n  %s", got)
	}
	if !strings.Contains(got, "context deadline exceeded") {
		t.Errorf("transport cause should be preserved, got:\n  %s", got)
	}
}

// TestRedactURLErr_Passthrough confirms a non-*url.Error is returned unchanged
// (so unrelated errors keep their full context and errors.Is chain).
func TestRedactURLErr_Passthrough(t *testing.T) {
	sentinel := errors.New("plain error")
	if got := redactURLErr(sentinel); !errors.Is(got, sentinel) {
		t.Errorf("non-url.Error must pass through unchanged, got: %v", got)
	}
}
