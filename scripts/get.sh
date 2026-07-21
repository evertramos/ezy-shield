#!/bin/sh
# get.ezyshield.com — EzyShield installer
# Usage: curl -sfL https://get.ezyshield.com | sudo sh
# For a specific version: curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=vX.Y.Z sh
#
# Environment variables:
#   EZYSHIELD_VERSION      Install a specific release (e.g., v0.1.0-rc.21). Must start with 'v'.
#   EZYSHIELD_BASE_URL     Install from a custom mirror. Overrides version selection.
#   EZYSHIELD_API_BASE_URL Override the GitHub API base (default https://api.github.com)
#                          used to resolve release metadata. For private API mirrors
#                          and testing only — asset downloads still use github.com
#                          unless EZYSHIELD_BASE_URL is also set.
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

# Native packages exist for deb/rpm systems — they add the systemd units,
# the service user, and clean upgrades via the package manager. This script
# still works everywhere; the hint is informational only (issue #99).
if command -v apt-get >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  echo "Tip: native .deb/.rpm packages are available — see the apt/dnf setup in the"
  echo "     install docs: https://github.com/evertramos/ezy-shield#install"
fi

# Source override: point the installer at a local mirror (air-gapped installs,
# CI, or the QEMU e2e harness) instead of GitHub Releases. When set, the
# "latest release" API lookup is skipped and artifacts + checksums.txt are
# fetched directly from ${EZYSHIELD_BASE_URL}. Because checksums.txt is fetched
# from the same base URL as the binaries, the SHA-256 comparison protects
# against transfer corruption but does NOT authenticate a compromised or
# malicious mirror — use this override only for trusted mirrors, air-gapped
# installs from artifacts you already vetted, or the local dev harness.
if [ -n "${EZYSHIELD_BASE_URL:-}" ]; then
  # Custom mirror (highest priority)
  VERSION="${EZYSHIELD_VERSION:-local}"
  BASE_URL="$EZYSHIELD_BASE_URL"
  echo "Installing EzyShield ${VERSION} (${SUFFIX}) from ${BASE_URL}..."
elif [ -n "${EZYSHIELD_VERSION:-}" ]; then
  # Specific version from GitHub Releases
  VERSION="$EZYSHIELD_VERSION"

  # Validate tag format (must start with 'v')
  case "$VERSION" in
    v*) ;;
    *) echo "Error: EZYSHIELD_VERSION must start with 'v' (got: $VERSION)"; exit 1 ;;
  esac

  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
  echo "Installing EzyShield ${VERSION} (${SUFFIX})..."
else
  # Default: fetch the latest STABLE release. GitHub's releases/latest
  # endpoint only ever returns non-prerelease releases; while every
  # published tag is still a release candidate (pre-v0.1.0), it 404s, and
  # that needs a clear, actionable message instead of a bare failure
  # (issue #235). This self-heals the moment v0.1.0 ships — no changes
  # needed here once a stable tag exists.
  echo "Fetching latest release..."
  API_BASE="${EZYSHIELD_API_BASE_URL:-https://api.github.com}"

  LATEST_RESP=$(curl -sL -w '\n%{http_code}' "${API_BASE}/repos/${REPO}/releases/latest" 2>/dev/null) || LATEST_RESP=""
  LATEST_HTTP_CODE=$(printf '%s' "$LATEST_RESP" | tail -n1)
  LATEST_BODY=$(printf '%s' "$LATEST_RESP" | sed '$d')

  VERSION=""
  if [ "$LATEST_HTTP_CODE" = "200" ]; then
    VERSION=$(printf '%s' "$LATEST_BODY" | grep '"tag_name"' | head -n1 | sed 's/.*"tag_name": *"//;s/".*//')
  fi

  if [ -z "$VERSION" ]; then
    if [ "$LATEST_HTTP_CODE" = "404" ]; then
      echo ""
      echo "No stable release has been published yet — every EzyShield release"
      echo "today is a release candidate (v0.1.0 is coming; this one-liner works"
      echo "with no extra flags the moment it ships)."
      echo ""
      echo "Two ways to install right now:"
      echo ""
      echo "  1) apt/dnf 'testing' repository (see the install docs for setup):"
      echo "     https://github.com/${REPO}#install"
      echo ""
      RC_TAG=$(curl -sfL "${API_BASE}/repos/${REPO}/releases?per_page=1" 2>/dev/null | grep '"tag_name"' | head -n1 | sed 's/.*"tag_name": *"//;s/".*//')
      # RC_TAG is API response data printed into a command line the operator
      # will copy-paste — only trust it if it looks like a plain release tag
      # (v + alphanumerics/dots/dashes); anything else degrades to the
      # generic pointer below, same as a failed lookup.
      case "$RC_TAG" in
        v*) case "$RC_TAG" in *[!A-Za-z0-9.-]*) RC_TAG="" ;; esac ;;
        *) RC_TAG="" ;;
      esac
      if [ -n "$RC_TAG" ]; then
        echo "  2) Pin the latest release candidate explicitly:"
        echo "     curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=${RC_TAG} sh"
      else
        echo "  2) Pin a specific release candidate (pick a tag from the list):"
        echo "     https://github.com/${REPO}/releases"
        echo "     curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=v0.1.0-rc.N sh"
      fi
      echo ""
    else
      echo "Error: could not determine latest version (HTTP ${LATEST_HTTP_CODE:-unreachable} from the GitHub API)"
      echo "Available releases: https://github.com/${REPO}/releases"
    fi
    exit 1
  fi

  echo "Installing EzyShield ${VERSION} (${SUFFIX})..."

  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

# Download binaries
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if ! curl -sfL "${BASE_URL}/checksums.txt" -o "${TMP}/checksums.txt"; then
  echo "Error: checksums.txt not found at ${BASE_URL}/checksums.txt"
  echo "The release ${VERSION} may not have pre-built binaries yet."
  echo "Available releases: https://github.com/${REPO}/releases"
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
