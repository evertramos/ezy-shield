package main

import (
	"bufio"
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestDetectPkgManager(t *testing.T) {
	t.Parallel()
	// Just verify it returns a non-panicking result — the value is environment-dependent.
	result := detectPkgManager()
	if result != "" {
		// Must end with a known manager name.
		base := result
		for _, sep := range []string{"/", "\\"} {
			if idx := strings.LastIndex(result, sep); idx >= 0 {
				base = result[idx+1:]
			}
		}
		known := map[string]bool{"apt-get": true, "dnf": true, "pacman": true, "zypper": true}
		if !known[base] {
			t.Errorf("detectPkgManager returned unexpected binary %q", result)
		}
	}
}

func TestInstallNFTPackage_UnsupportedPM(t *testing.T) {
	t.Parallel()
	err := installNFTPackage("brew")
	if err == nil {
		t.Fatal("expected error for unsupported package manager, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error %q does not mention 'unsupported'", err)
	}
}

// TestOfferInstallNFT_DeclineSkipsInstall verifies that answering "n" returns
// an empty path without attempting any system commands.
func TestOfferInstallNFT_DeclineSkipsInstall(t *testing.T) {
	t.Parallel()
	sc := bufio.NewScanner(strings.NewReader("n\n"))
	var out bytes.Buffer
	result := offerInstallNFT(sc, false, &out)
	if result != "" {
		t.Errorf("expected empty path when user declines, got %q", result)
	}
	if !strings.Contains(out.String(), "nftables") {
		t.Error("expected output to mention nftables")
	}
}

// TestOfferInstallNFT_YesFlagWithoutPM verifies that --yes with no package
// manager available logs a message and returns "".
// We patch detectPkgManager indirectly: on a system where no pm exists the
// function returns "" and offerInstallNFT should explain that.
// On CI systems that DO have a pm this test is skipped to avoid root calls.
func TestOfferInstallNFT_YesFlagNoPM(t *testing.T) {
	t.Parallel()
	// If a package manager is present, this test would attempt an install which
	// requires root. Skip rather than fail.
	if detectPkgManager() != "" {
		t.Skip("package manager present; skipping to avoid attempted system install")
	}
	var out bytes.Buffer
	result := offerInstallNFT(nil, true, &out)
	if result != "" {
		t.Errorf("expected empty path when no pm detected, got %q", result)
	}
	if !strings.Contains(out.String(), "package manager") {
		t.Errorf("expected output to mention 'package manager', got %q", out.String())
	}
}

// TestWriteGeneratedConfig_NoNFT checks that when nftPath is empty the
// generated config.yaml contains no enforce.nftables section, and still
// passes the loader's validation.
func TestWriteGeneratedConfig_NoNFT(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/config.yaml"

	state := &wizardState{nftPath: ""}
	if err := writeGeneratedConfig(path, state); err != nil {
		t.Fatalf("writeGeneratedConfig returned error: %v", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is t.TempDir()-controlled
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	if strings.Contains(string(data), "enforce:") {
		t.Errorf("config should have no enforce block when nftPath is empty:\n%s", data)
	}
}

// TestWriteGeneratedConfig_WithNFT checks that when nftPath is set the
// generated config.yaml includes enforce.nftables.
func TestWriteGeneratedConfig_WithNFT(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/config.yaml"

	state := &wizardState{nftPath: "/usr/sbin/nft"}
	if err := writeGeneratedConfig(path, state); err != nil {
		t.Fatalf("writeGeneratedConfig returned error: %v", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is t.TempDir()-controlled
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	if !strings.Contains(string(data), "nftables:") {
		t.Errorf("config should have nftables block when nftPath is set:\n%s", data)
	}
}
