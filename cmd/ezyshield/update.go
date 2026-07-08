package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/update"
)

const (
	envUpdateURL      = "EZYSHIELD_UPDATE_URL"
	checksumsFilename = "checksums.txt"
	verifyExecTimeout = 5 * time.Second
)

// newClientHook constructs the update client. Override in tests to inject an
// HTTP client that trusts httptest's self-signed cert; production code uses
// the package default (system roots, strict TLS).
var newClientHook = update.NewClient

// updateOptions captures everything an update needs that can be overridden by
// flags or env vars. Exposed as a struct so update_test.go can drive the
// orchestrator without going through cobra.
type updateOptions struct {
	checkOnly      bool
	pinnedVersion  string
	currentVersion string

	apiBaseURL string // override default api.github.com
	repo       string // override evertramos/ezy-shield

	binaryPath   string // resolved path of self-binary
	enforcerPath string // sibling enforcer binary

	goos string
	arch string

	// runVerify execs path with "--version" to confirm the binary is runnable.
	// Injectable so tests don't need a real binary.
	runVerify func(ctx context.Context, path string) error

	// isRoot reports whether the process can write to system binary paths.
	// Injectable for tests.
	isRoot func() bool

	out io.Writer
}

func newUpdateCmd() *cobra.Command {
	var (
		checkOnly     bool
		pinnedVersion string
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Self-update ezyshield from GitHub Releases",
		Long: `Check GitHub Releases for a newer ezyshield, verify SHA256 checksums,
and atomically replace the on-disk binaries (ezyshield and ezyshield-enforcer).

By default fetches from the public repo evertramos/ezy-shield. Override the
release source with the EZYSHIELD_UPDATE_URL environment variable (e.g. a
private mirror): point it at the GitHub API base, e.g. https://api.github.com.

This command does NOT restart services. After a successful update, run:

  sudo systemctl restart ezyshield ezyshield-enforcer`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			selfPath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolve own binary path: %w", err)
			}
			selfPath, err = filepath.EvalSymlinks(selfPath)
			if err != nil {
				return fmt.Errorf("resolve symlinks: %w", err)
			}

			apiBaseURL, repo := resolveUpdateSource(os.Getenv(envUpdateURL))

			opts := updateOptions{
				checkOnly:      checkOnly,
				pinnedVersion:  pinnedVersion,
				currentVersion: version,
				apiBaseURL:     apiBaseURL,
				repo:           repo,
				binaryPath:     selfPath,
				enforcerPath:   filepath.Join(filepath.Dir(selfPath), "ezyshield-enforcer"),
				goos:           runtime.GOOS,
				arch:           runtime.GOARCH,
				runVerify:      verifyBinary,
				isRoot:         func() bool { return os.Geteuid() == 0 },
				out:            cmd.OutOrStdout(),
			}
			return runUpdate(cmd.Context(), opts)
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "check for updates without applying")
	cmd.Flags().StringVar(&pinnedVersion, "version", "", "install a specific release tag (e.g. v0.2.0)")

	return cmd
}

// resolveUpdateSource maps EZYSHIELD_UPDATE_URL to (apiBase, repo). The env
// var, if set, must be the API base — we keep using the configured repo path
// so private mirrors mirror /repos/{owner}/{name}/releases/latest verbatim.
func resolveUpdateSource(envURL string) (apiBase, repo string) {
	repo = update.DefaultRepo
	apiBase = update.DefaultAPIBaseURL
	envURL = strings.TrimSpace(envURL)
	if envURL == "" {
		return apiBase, repo
	}
	u, err := url.Parse(envURL)
	if err != nil || u.Scheme != "https" {
		// Fall back silently to defaults rather than failing — the caller will
		// see "Checking..." against the public repo. We intentionally don't
		// surface the bad value (might contain a token).
		return update.DefaultAPIBaseURL, update.DefaultRepo
	}
	// Strip any trailing slash; the client builds /repos/... onto this.
	apiBase = strings.TrimSuffix(envURL, "/")
	return apiBase, repo
}

func runUpdate(ctx context.Context, opts updateOptions) error {
	if opts.out == nil {
		opts.out = io.Discard
	}
	out := &errWriter{w: opts.out}

	if opts.goos != "linux" {
		return fmt.Errorf("ezyshield self-update only supports Linux (got: %s)", opts.goos)
	}
	if opts.arch != "amd64" && opts.arch != "arm64" {
		return fmt.Errorf("unsupported architecture: %s (supported: amd64, arm64)", opts.arch)
	}

	client := newClientHook()
	if client == nil {
		return errors.New("update client unavailable (newClientHook returned nil)")
	}
	client.APIBaseURL = opts.apiBaseURL
	client.Repo = opts.repo

	rel, err := fetchTargetRelease(ctx, client, opts.pinnedVersion)
	if err != nil {
		return err
	}

	if opts.pinnedVersion == "" {
		cmp, err := update.CompareSemver(opts.currentVersion, rel.TagName)
		switch {
		case err != nil:
			// Current version isn't semver (e.g. "dev"). Treat as "always update".
			out.printf("Current version %q is not semver — proceeding with %s\n",
				opts.currentVersion, rel.TagName)
		case cmp >= 0:
			out.printf("Already up to date (%s)\n", opts.currentVersion)
			return out.err
		}
	}

	if opts.checkOnly {
		out.printf("Current: %s\nLatest:  %s\nUpdate available. Run: sudo ezyshield update\n",
			opts.currentVersion, rel.TagName)
		return out.err
	}

	// Pinned: still print the transition for the operator's log.
	if opts.pinnedVersion != "" {
		out.printf("Installing %s (current: %s)\n", rel.TagName, opts.currentVersion)
	} else {
		out.printf("Checking for updates... %s available\n", rel.TagName)
	}

	if !opts.isRoot() {
		return fmt.Errorf("update requires root (binaries in %s)", filepath.Dir(opts.binaryPath))
	}

	suffix := "linux-" + opts.arch
	mainName := "ezyshield-" + suffix
	enforcerName := "ezyshield-enforcer-" + suffix

	mainAsset, ok := rel.FindAsset(mainName)
	if !ok {
		return fmt.Errorf("release %s has no asset %q", rel.TagName, mainName)
	}
	enforcerAsset, ok := rel.FindAsset(enforcerName)
	if !ok {
		return fmt.Errorf("release %s has no asset %q", rel.TagName, enforcerName)
	}
	sumsAsset, ok := rel.FindAsset(checksumsFilename)
	if !ok {
		return fmt.Errorf("release %s has no asset %q — cannot verify", rel.TagName, checksumsFilename)
	}

	sums, err := client.DownloadChecksums(ctx, sumsAsset.URL)
	if err != nil {
		return fmt.Errorf("fetch checksums: %w", err)
	}
	mainSHA, ok := sums[mainName]
	if !ok {
		return fmt.Errorf("checksums.txt has no entry for %q", mainName)
	}
	enforcerSHA, ok := sums[enforcerName]
	if !ok {
		return fmt.Errorf("checksums.txt has no entry for %q", enforcerName)
	}

	specs := []update.AssetSpec{
		{Name: mainName, URL: mainAsset.URL, WantSHA256: mainSHA, InstallPath: opts.binaryPath},
		{Name: enforcerName, URL: enforcerAsset.URL, WantSHA256: enforcerSHA, InstallPath: opts.enforcerPath},
	}

	// Phase 1: download + verify checksums + verify --version into temp files,
	// without touching the live binaries. If any spec fails, no install paths
	// are mutated.
	tmpPaths := make([]string, len(specs))
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		for _, p := range tmpPaths {
			if p != "" {
				_ = os.Remove(p)
			}
		}
	}()

	for i, spec := range specs {
		out.printf("Downloading %s... ", spec.Name)
		tmp, err := update.DownloadVerified(ctx, client, spec)
		if err != nil {
			out.println("FAILED")
			return err
		}
		tmpPaths[i] = tmp
		out.println("done")
		out.printf("Verifying checksum... OK\n")

		// Make executable before verify step
		if err := os.Chmod(tmp, 0755); err != nil {
			return fmt.Errorf("chmod temp binary %s: %w", spec.Name, err)
		}

		if opts.runVerify != nil {
			if err := opts.runVerify(ctx, tmp); err != nil {
				return fmt.Errorf("downloaded %s does not execute: %w", spec.Name, err)
			}
		}
	}

	// Phase 2: install. Per-file rename is atomic; if the second rename fails,
	// the first binary is the new one and the second the old one — we surface
	// that clearly so the operator can re-run or roll back.
	out.printf("Installing... ")
	for i, spec := range specs {
		if err := update.AtomicReplace(tmpPaths[i], spec.InstallPath, 0o755); err != nil {
			out.println("FAILED")
			return fmt.Errorf("install %s: %w", spec.Name, err)
		}
	}
	out.println("done")
	cleanup = false

	out.printf("\nUpdated: %s → %s\n", opts.currentVersion, rel.TagName)
	out.println("Restart to apply: sudo systemctl restart ezyshield ezyshield-enforcer")
	return out.err
}

// errWriter wraps an io.Writer and accumulates the first write error so call
// sites don't have to plumb error checks through every status print. The
// accumulated error is returned via the runUpdate return path.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

func (e *errWriter) println(s string) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintln(e.w, s)
}

func fetchTargetRelease(ctx context.Context, c *update.Client, pinned string) (*update.Release, error) {
	if pinned != "" {
		return c.ReleaseByTag(ctx, pinned)
	}
	return c.LatestRelease(ctx)
}

// verifyBinary execs path with --version under a short timeout. Returning nil
// confirms the binary loaded (correct arch, not truncated, ELF intact).
func verifyBinary(ctx context.Context, path string) error {
	vctx, cancel := context.WithTimeout(ctx, verifyExecTimeout)
	defer cancel()
	// G204: path is a temp file we just wrote inside the destination directory,
	// derived from os.Executable() — not log-derived.
	out, err := exec.CommandContext(vctx, path, "--version").CombinedOutput() //nolint:gosec
	if err != nil {
		return fmt.Errorf("exec %s --version: %w (output: %s)", filepath.Base(path), err, truncate(out, 200))
	}
	if len(out) == 0 {
		return errors.New("binary produced no output for --version")
	}
	return nil
}

// truncate cuts b to at most n bytes for safe inclusion in error messages.
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...(truncated)"
}
