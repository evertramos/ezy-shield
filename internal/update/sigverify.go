package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Cosign keyless-verification pins for release signatures. These MUST match
// docs/content/en/security/verifying-releases.md — the docs command and this
// code verify the same trust chain: checksums.txt was produced by THIS
// repository's release workflow on GitHub's OIDC issuer, not by a compromised
// token, a hijacked release, or a mirror.
const (
	// CosignOIDCIssuer is GitHub Actions' OIDC token issuer.
	CosignOIDCIssuer = "https://token.actions.githubusercontent.com"
	// CosignIdentityRegexp pins repository and workflow file. The ref portion
	// accepts both release trigger paths: a pushed tag (refs/tags/vX.Y.Z) and
	// a workflow_dispatch from main (stable) or dev (release candidates).
	CosignIdentityRegexp = `^https://github\.com/evertramos/ezy-shield/\.github/workflows/release\.yaml@refs/(tags/v[0-9][^ ]*|heads/(main|dev))$`
)

// ErrCosignNotFound reports that the cosign binary is not installed. Callers
// decide the policy (the updater fails closed unless --allow-unsigned is
// given — a distinct sentinel so that opt-out can never swallow a real
// verification failure).
var ErrCosignNotFound = errors.New("cosign not found in PATH")

// CosignExecFunc runs cosign with args and returns its combined output. It is
// injectable so the verification flow is testable without cosign or network
// access to the Sigstore infrastructure.
type CosignExecFunc func(ctx context.Context, args ...string) ([]byte, error)

// RealCosignExec locates cosign in PATH and executes it. Returns
// ErrCosignNotFound when the binary is absent.
func RealCosignExec(ctx context.Context, args ...string) ([]byte, error) {
	path, err := exec.LookPath("cosign")
	if err != nil {
		return nil, ErrCosignNotFound
	}
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // fixed binary name resolved via LookPath; args are built by VerifyChecksumsSignature, not user input
	return cmd.CombinedOutput()
}

// VerifyChecksumsSignature verifies the cosign keyless signature over the raw
// checksums.txt bytes, using the detached signature and certificate published
// with the release (checksums.txt.sig / checksums.txt.pem).
//
// The three byte slices are written to a private temp dir because cosign
// verify-blob operates on files. Any verification failure — wrong identity,
// wrong issuer, tampered checksums — returns an error carrying cosign's
// output; the caller must treat that as fatal for the update.
func VerifyChecksumsSignature(ctx context.Context, run CosignExecFunc, checksums, sig, cert []byte) error {
	dir, err := os.MkdirTemp("", "ezyshield-sigverify-*")
	if err != nil {
		return fmt.Errorf("sigverify: temp dir: %w", err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // best-effort cleanup of temp files

	files := map[string][]byte{
		"checksums.txt":     checksums,
		"checksums.txt.sig": sig,
		"checksums.txt.pem": cert,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return fmt.Errorf("sigverify: write %s: %w", name, err)
		}
	}

	out, err := run(ctx,
		"verify-blob",
		"--certificate", filepath.Join(dir, "checksums.txt.pem"),
		"--signature", filepath.Join(dir, "checksums.txt.sig"),
		"--certificate-oidc-issuer", CosignOIDCIssuer,
		"--certificate-identity-regexp", CosignIdentityRegexp,
		filepath.Join(dir, "checksums.txt"),
	)
	if err != nil {
		if errors.Is(err, ErrCosignNotFound) {
			return err
		}
		return fmt.Errorf("sigverify: cosign verify-blob failed: %w (output: %s)", err, out)
	}
	return nil
}
