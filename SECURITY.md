# Security Policy

EzyShield is a security tool, so we take vulnerabilities seriously.

## Reporting a vulnerability
Please do NOT open a public issue. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") or email the maintainer (see profile).
You will get an acknowledgment within 72 hours.

## Scope of special interest
- Anything that could ban an allowlisted IP or the admin's own session
- Privilege escalation via the enforcer helper or plugins
- Prompt injection through log content influencing AI verdicts beyond policy bounds
- Dashboard exposure beyond localhost

## Supply chain
Releases are verifiable end-to-end:

- `checksums.txt` is signed with **cosign keyless** inside the GitHub Actions
  release workflow (OIDC identity, recorded in the Sigstore public
  transparency log); `checksums.txt.sig`/`.pem` are attached to every
  release. One verified signature transitively authenticates every artifact.
- Each artifact ships an **SPDX SBOM** (`<artifact>.spdx.json`, generated
  with syft).
- The install script (`get.ezyshield.com`) verifies the signature
  automatically when `cosign` is installed, and warns (without failing)
  when it is not. Custom-mirror installs are gated behind an explicit
  `--local` flag + `EZYSHIELD_LOCAL_ACK=1` because that path cannot
  authenticate its source.
- deb/rpm packages are additionally GPG-verified by apt/dnf against the
  package-repository signing key.

Exact verification commands (pinned certificate identity and issuer):
[docs → security → Verifying Releases](docs/content/en/security/verifying-releases.md).

## Supported versions
Pre-1.0: only the latest release receives fixes.
