#!/bin/sh
# get.ezyshield.com — EzyShield installer
# Usage: curl -sfL https://get.ezyshield.com | sh
set -eu

REPO="evertramos/ezy-shield"
INSTALL_DIR="/usr/local/bin"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Error: unsupported architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
  echo "Error: EzyShield only supports Linux (got: $OS)"
  exit 1
fi

SUFFIX="${OS}-${ARCH}"

# Source override: point the installer at a local mirror (air-gapped installs,
# CI, or the QEMU e2e harness) instead of GitHub Releases. When set, the
# "latest release" API lookup is skipped and artifacts + checksums.txt are
# fetched directly from ${EZYSHIELD_BASE_URL}. Because checksums.txt is fetched
# from the same base URL as the binaries, the SHA-256 comparison protects
# against transfer corruption but does NOT authenticate a compromised or
# malicious mirror — use this override only for trusted mirrors, air-gapped
# installs from artifacts you already vetted, or the local dev harness.
if [ -n "${EZYSHIELD_BASE_URL:-}" ]; then
  VERSION="${EZYSHIELD_VERSION:-local}"
  BASE_URL="$EZYSHIELD_BASE_URL"
  echo "Installing EzyShield ${VERSION} (${SUFFIX}) from ${BASE_URL}..."
else
  # Get latest version
  echo "Fetching latest release..."
  VERSION=$(curl -sfL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//')

  if [ -z "$VERSION" ]; then
    echo "Error: could not determine latest version"
    exit 1
  fi

  echo "Installing EzyShield ${VERSION} (${SUFFIX})..."

  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

# Download binaries
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if ! curl -sfL "${BASE_URL}/checksums.txt" -o "${TMP}/checksums.txt"; then
  echo "Error: checksums.txt not found in release ${VERSION}. Cannot verify integrity."
  exit 1
fi
if ! curl -sfL "${BASE_URL}/ezyshield-${SUFFIX}" -o "${TMP}/ezyshield"; then
  echo "Error: binary not found at ${BASE_URL}/ezyshield-${SUFFIX}"
  echo "The release ${VERSION} may not have pre-built binaries yet."
  echo "Build from source: go build -o ezyshield ./cmd/ezyshield"
  exit 1
fi
if ! curl -sfL "${BASE_URL}/ezyshield-enforcer-${SUFFIX}" -o "${TMP}/ezyshield-enforcer"; then
  echo "Error: binary not found at ${BASE_URL}/ezyshield-enforcer-${SUFFIX}"
  exit 1
fi

# Verify checksums
cd "$TMP"
EXPECTED_MAIN=$(grep "ezyshield-${SUFFIX}$" checksums.txt | awk '{print $1}')
EXPECTED_ENF=$(grep "ezyshield-enforcer-${SUFFIX}$" checksums.txt | awk '{print $1}')
ACTUAL_MAIN=$(sha256sum ezyshield | awk '{print $1}')
ACTUAL_ENF=$(sha256sum ezyshield-enforcer | awk '{print $1}')

if [ "$EXPECTED_MAIN" != "$ACTUAL_MAIN" ]; then
  echo "Error: checksum mismatch for ezyshield"
  exit 1
fi
if [ "$EXPECTED_ENF" != "$ACTUAL_ENF" ]; then
  echo "Error: checksum mismatch for ezyshield-enforcer"
  exit 1
fi

# Install
install -m 755 ezyshield "${INSTALL_DIR}/ezyshield"
install -m 755 ezyshield-enforcer "${INSTALL_DIR}/ezyshield-enforcer"

echo ""
echo "✅ EzyShield ${VERSION} installed to ${INSTALL_DIR}/"
echo ""
echo "Next steps:"
echo "  sudo ezyshield init    # interactive setup wizard"
echo ""
