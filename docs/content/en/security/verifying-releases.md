---
title: Verifying Releases
description: Cryptographically verify EzyShield release artifacts with cosign
order: 2
---

# Verifying Releases

Every EzyShield release signs its `checksums.txt` with
[cosign keyless signing](https://docs.sigstore.dev/cosign/verifying/verify/):
the signature is produced inside the GitHub Actions release workflow using
its OIDC identity, recorded in the Sigstore public transparency log, and
attached to the release as `checksums.txt.sig` (signature) and
`checksums.txt.pem` (certificate). There is no private key to steal or
manage — the trust anchor is the workflow identity itself.

Because `checksums.txt` carries the SHA-256 of every artifact, one verified
signature transitively authenticates all of them: raw binaries, tarballs,
and deb/rpm packages. Each artifact also ships an SPDX SBOM
(`<artifact>.spdx.json`) generated with [syft](https://github.com/anchore/syft).

## What verification proves

A successful `cosign verify-blob` proves `checksums.txt` was produced by the
`release.yaml` workflow **of this repository**, on GitHub's infrastructure —
not by a compromised GitHub token, a hijacked release, or a mirror. It does
not prove the source code is bug-free; it proves the artifacts you hold are
the ones that workflow built.

## Verify a release

```bash
VERSION=v0.1.0   # the tag you are verifying
BASE=https://github.com/evertramos/ezy-shield/releases/download/${VERSION}

curl -sfLO "${BASE}/checksums.txt"
curl -sfLO "${BASE}/checksums.txt.sig"
curl -sfLO "${BASE}/checksums.txt.pem"

cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    '^https://github\.com/evertramos/ezy-shield/\.github/workflows/release\.yaml@refs/(tags/v[0-9][^ ]*|heads/(main|dev))$' \
  checksums.txt
```

Expected output: `Verified OK`.

The identity regexp pins **repository and workflow file**. The ref portion
accepts both release trigger paths: a pushed tag (`refs/tags/vX.Y.Z`) and a
`workflow_dispatch` from `main` (stable) or `dev` (release candidates) —
in the dispatch case the certificate carries the branch the workflow ran
from, not the tag it created.

Then check the artifact you downloaded against the now-verified checksums:

```bash
curl -sfLO "${BASE}/ezyshield-linux-amd64"
sha256sum --check --ignore-missing checksums.txt
```

## Notes

- Releases published **before** signing landed (early v0.1.0 release
  candidates) have no `.sig`/`.pem` assets; for those, integrity rests on
  TLS to `github.com` only.
- The `get.ezyshield.com` install script performs this same verification
  automatically when `cosign` is installed on the host, and prints a warning
  (without failing) when it is not.
- deb/rpm packages installed through the package repository are additionally
  GPG-verified by apt/dnf against the repository signing key.
- SBOMs: download `<artifact>.spdx.json` from the release page to audit the
  exact module graph an artifact was built from (e.g. feed it to
  `grype`/`osv-scanner` for vulnerability scanning).
