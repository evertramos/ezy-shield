package enrich

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeTarGz builds an in-memory tar.gz with a single entry named name and body b.
func makeTarGz(t *testing.T, name string, b []byte) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{
		Name:     name,
		Typeflag: tar.TypeReg,
		Size:     int64(len(b)),
		Mode:     0o640,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar WriteHeader: %v", err)
	}
	if _, err := tw.Write(b); err != nil {
		t.Fatalf("tar Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestExtractMMDB_Normal(t *testing.T) {
	content := []byte("fake mmdb content")
	r := makeTarGz(t, "GeoLite2-Country/GeoLite2-Country.mmdb", content)

	dest := filepath.Join(t.TempDir(), "country.mmdb")
	if err := extractMMDB(r, dest); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := os.ReadFile(dest) //nolint:gosec
	if err != nil {
		t.Fatalf("reading dest: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("dest content mismatch: got %q, want %q", got, content)
	}
}

func TestExtractMMDB_NoMMDB(t *testing.T) {
	r := makeTarGz(t, "README.txt", []byte("hello"))

	dest := filepath.Join(t.TempDir(), "country.mmdb")
	err := extractMMDB(r, dest)
	if err == nil {
		t.Fatal("want error for archive with no .mmdb, got nil")
	}
	if !strings.Contains(err.Error(), "no .mmdb") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestExtractMMDB_TruncationDetected(t *testing.T) {
	// Patch maxMMDBBytes to a tiny value so we can trigger truncation cheaply.
	orig := maxMMDBBytes
	const tiny = 4
	// We can't reassign the const, so we'll build an archive with tiny+1 bytes.
	// Instead, use a local variable to simulate the limit via a sub-test helper.
	_ = orig // keep linter happy

	// Write a file that is exactly tiny+1 bytes to trigger the limit guard.
	// We test extractMMDB directly with a custom limit by wrapping the logic.
	// Since the const can't be changed in tests, we write an archive whose .mmdb
	// is exactly maxMMDBBytes+1 bytes. That would be 200 MiB+1 in practice.
	// Instead we test the detection logic with a smaller synthetic constant by
	// calling the unexported helper extractMMDBWithLimit.
	content := bytes.Repeat([]byte("x"), tiny+1)
	r := makeTarGz(t, "GeoLite2-Country.mmdb", content)

	dest := filepath.Join(t.TempDir(), "country.mmdb")
	err := extractMMDBWithLimit(r, dest, tiny)
	if err == nil {
		t.Fatal("want error when mmdb exceeds size limit, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("unexpected error message: %v", err)
	}
	// Temp file must not be left behind.
	tmp := dest + ".tmp"
	if _, statErr := os.Stat(tmp); !os.IsNotExist(statErr) {
		t.Errorf("tmp file %s should have been removed on truncation error", tmp)
	}
	// Dest file must not exist (rename never happened).
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Errorf("dest file %s should not exist after truncation error", dest)
	}
}

func TestExtractMMDB_ExactLimit(t *testing.T) {
	// A file whose size equals the limit exactly must succeed (no false positive).
	const tiny = 4
	content := bytes.Repeat([]byte("y"), tiny)
	r := makeTarGz(t, "GeoLite2-ASN.mmdb", content)

	dest := filepath.Join(t.TempDir(), "asn.mmdb")
	if err := extractMMDBWithLimit(r, dest, tiny); err != nil {
		t.Fatalf("file at exact limit must not error, got: %v", err)
	}
	got, err := os.ReadFile(dest) //nolint:gosec
	if err != nil {
		t.Fatalf("reading dest: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch at exact limit")
	}
}

func TestExtractMMDB_CorruptGzip(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "country.mmdb")
	err := extractMMDB(strings.NewReader("not gzip data"), dest)
	if err == nil {
		t.Fatal("want error on corrupt gzip, got nil")
	}
}

func TestExtractMMDB_SkipsNonRegular(t *testing.T) {
	// Archive with a directory entry before the .mmdb — must still find the file.
	content := []byte("real content")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Directory entry
	_ = tw.WriteHeader(&tar.Header{Name: "dir/", Typeflag: tar.TypeDir, Mode: 0o750})

	// Real .mmdb entry
	hdr := &tar.Header{
		Name:     "dir/GeoLite2-Country.mmdb",
		Typeflag: tar.TypeReg,
		Size:     int64(len(content)),
		Mode:     0o640,
	}
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gw.Close()

	dest := filepath.Join(t.TempDir(), "country.mmdb")
	if err := extractMMDB(bytes.NewReader(buf.Bytes()), dest); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
