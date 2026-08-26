// SPDX-License-Identifier: AGPL-3.0-only

package update

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestVerifyChecksumsSignature_PinsIdentity asserts the cosign invocation
// carries the pinned OIDC issuer and identity regexp — the two flags that turn
// "a valid Sigstore signature" into "a signature from THIS repo's release
// workflow" (issue #322).
func TestVerifyChecksumsSignature_PinsIdentity(t *testing.T) {
	var gotArgs []string
	run := func(_ context.Context, args ...string) ([]byte, error) {
		gotArgs = args
		// The files must exist and carry the exact bytes at call time.
		for i, flag := range args {
			if flag == "--certificate" || flag == "--signature" {
				if _, err := os.Stat(args[i+1]); err != nil {
					t.Errorf("%s file missing at call time: %v", flag, err)
				}
			}
		}
		return []byte("Verified OK"), nil
	}

	err := VerifyChecksumsSignature(context.Background(), run,
		[]byte("aabb  ezyshield-linux-amd64\n"), []byte("SIG"), []byte("CERT"))
	if err != nil {
		t.Fatalf("VerifyChecksumsSignature: %v", err)
	}

	joined := strings.Join(gotArgs, " ")
	for _, want := range []string{
		"verify-blob",
		"--certificate-oidc-issuer " + CosignOIDCIssuer,
		"--certificate-identity-regexp " + CosignIdentityRegexp,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("cosign args missing %q:\n%s", want, joined)
		}
	}
}

// TestVerifyChecksumsSignature_FailurePropagates asserts a cosign failure is
// fatal and carries the tool output for diagnosis.
func TestVerifyChecksumsSignature_FailurePropagates(t *testing.T) {
	run := func(_ context.Context, _ ...string) ([]byte, error) {
		return []byte("Error: no matching signatures"), errors.New("exit status 1")
	}
	err := VerifyChecksumsSignature(context.Background(), run, []byte("x"), []byte("y"), []byte("z"))
	if err == nil {
		t.Fatal("expected verification failure to propagate")
	}
	if !strings.Contains(err.Error(), "no matching signatures") {
		t.Errorf("error should carry cosign output, got: %v", err)
	}
}

// TestVerifyChecksumsSignature_CosignMissing surfaces ErrCosignNotFound
// unwrapped so callers can apply the warn-and-continue policy.
func TestVerifyChecksumsSignature_CosignMissing(t *testing.T) {
	run := func(_ context.Context, _ ...string) ([]byte, error) {
		return nil, ErrCosignNotFound
	}
	err := VerifyChecksumsSignature(context.Background(), run, []byte("x"), []byte("y"), []byte("z"))
	if !errors.Is(err, ErrCosignNotFound) {
		t.Fatalf("want ErrCosignNotFound, got: %v", err)
	}
}
