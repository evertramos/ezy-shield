package enrich

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	updateInterval  = 7 * 24 * time.Hour
	mmdbBaseURL     = "https://download.maxmind.com/app/geoip_download"
	downloadTimeout = 5 * time.Minute
	maxMMDBBytes    = 200 << 20 // 200 MiB hard cap to guard against zip bombs
)

// Updater downloads GeoLite2-Country and GeoLite2-ASN mmdb files from MaxMind
// on a weekly schedule, then hot-reloads the associated Enricher.
type Updater struct {
	enricher    *Enricher
	licenseKey  string // resolved value — never logged
	countryPath string
	asnPath     string
}

// NewUpdater creates an Updater. licenseKey must be the resolved secret value
// (already fetched from the environment); it is never written to logs or errors.
func NewUpdater(e *Enricher, licenseKey, countryPath, asnPath string) *Updater {
	return &Updater{
		enricher:    e,
		licenseKey:  licenseKey,
		countryPath: countryPath,
		asnPath:     asnPath,
	}
}

// Run starts the weekly update loop. It performs an immediate download when
// either DB file is absent, then ticks weekly. Blocks until ctx is cancelled.
func (u *Updater) Run(ctx context.Context) {
	if !fileExists(u.countryPath) || !fileExists(u.asnPath) {
		if err := u.update(ctx); err != nil {
			slog.WarnContext(ctx, "enrich: initial DB download failed", "err", err)
		}
	}

	t := time.NewTicker(updateInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := u.update(ctx); err != nil {
				slog.WarnContext(ctx, "enrich: weekly DB update failed", "err", err)
			}
		}
	}
}

func (u *Updater) update(ctx context.Context) error {
	if err := u.downloadEdition(ctx, "GeoLite2-Country", u.countryPath); err != nil {
		return fmt.Errorf("GeoLite2-Country: %w", err)
	}
	if err := u.downloadEdition(ctx, "GeoLite2-ASN", u.asnPath); err != nil {
		return fmt.Errorf("GeoLite2-ASN: %w", err)
	}
	u.enricher.Reload()
	slog.InfoContext(ctx, "enrich: databases updated and reloaded")
	return nil
}

// downloadEdition fetches a MaxMind edition tar.gz and extracts the .mmdb to destPath.
// The license key appears only in the HTTPS request URL and is never logged.
func (u *Updater) downloadEdition(ctx context.Context, edition, destPath string) error {
	dlCtx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	// Build URL with proper encoding so the license key never leaks in error messages.
	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, mmdbBaseURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	q := req.URL.Query()
	q.Set("edition_id", edition)
	q.Set("license_key", u.licenseKey)
	q.Set("suffix", "tar.gz")
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Wrap without including the URL so the key is not in the error string.
		return fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d for edition %s", resp.StatusCode, edition)
	}

	return extractMMDB(resp.Body, destPath)
}

// extractMMDB reads a tar.gz stream and writes the first .mmdb entry to destPath
// using an atomic rename (write to .tmp then rename). Size is capped at maxMMDBBytes.
func extractMMDB(r io.Reader, destPath string) error {
	return extractMMDBWithLimit(r, destPath, maxMMDBBytes)
}

func extractMMDBWithLimit(r io.Reader, destPath string, limit int64) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close() //nolint:errcheck

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}

		// Write the clean path the caller requested — never use the archive path.
		if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
			return fmt.Errorf("mkdir: %w", err)
		}

		tmp := destPath + ".tmp"
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640) //nolint:gosec
		if err != nil {
			return fmt.Errorf("create tmp: %w", err)
		}

		n, err := io.Copy(f, io.LimitReader(tr, limit))
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("write: %w", err)
		}
		// Detect silent truncation: if we consumed the full limit, probe for more.
		if n == limit {
			var probe [1]byte
			if nr, _ := tr.Read(probe[:]); nr > 0 {
				_ = f.Close()
				_ = os.Remove(tmp)
				return fmt.Errorf("mmdb exceeds %d MiB size limit", limit>>20)
			}
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("close tmp: %w", err)
		}
		if err := os.Rename(tmp, destPath); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("rename: %w", err)
		}
		return nil
	}
	return fmt.Errorf("no .mmdb file found in archive")
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
