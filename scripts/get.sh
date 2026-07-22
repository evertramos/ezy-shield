#!/bin/sh
# get.ezyshield.com — EzyShield installer
# Usage: curl -sfL https://get.ezyshield.com | sudo sh
# For a specific version: curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=vX.Y.Z sh
# To uninstall a script install: curl -sfL https://get.ezyshield.com | sudo sh -s -- --uninstall
#
# Install method (issue #240 — package-first, tailscale/docker install-script
# pattern): when this host has apt-get or dnf/yum AND the EzyShield package
# repository is reachable, this script sets up the repo (GPG key + source
# entry, same as the manual apt/dnf docs) and installs via the package
# manager. Raw binaries in /usr/local/bin are used only when: the host has
# no deb/rpm tooling, EZYSHIELD_BASE_URL points at a custom mirror,
# EZYSHIELD_METHOD=binary is set explicitly, or the package repo setup /
# reachability check fails (loud warning, automatic fallback — the install
# still completes).
#
# Environment variables:
#   EZYSHIELD_VERSION          Install a specific release (e.g., v0.1.0-rc.21).
#                               Must start with 'v'. Binary mode only.
#   EZYSHIELD_BASE_URL         Install from a custom mirror. Overrides version
#                               selection and forces binary mode (air-gapped).
#   EZYSHIELD_API_BASE_URL     Override the GitHub API base (default
#                               https://api.github.com) used to resolve
#                               release metadata. For private API mirrors and
#                               testing only — asset downloads still use
#                               github.com unless EZYSHIELD_BASE_URL is also set.
#   EZYSHIELD_PACKAGES_BASE_URL Override the package repo base (default
#                               https://packages.ezyshield.com). For private
#                               mirrors and testing only.
#   EZYSHIELD_METHOD            'auto' (default), 'packages', or 'binary'.
#                               'binary' skips package-manager detection
#                               entirely and always installs raw binaries.
#   EZYSHIELD_CLEANUP           Set to 1 to non-interactively remove a
#                               previous script install (binaries in
#                               /usr/local/bin, units in /etc/systemd/system)
#                               that would shadow a fresh package install,
#                               instead of only printing the cleanup commands.
#   EZYSHIELD_UNINSTALL          Set to 1 (equivalent to --uninstall) to remove
#                               script-install artifacts and exit. Never
#                               touches package-managed files.
#   EZYSHIELD_ROOT               Internal/test-only path prefix (DESTDIR-style)
#                               applied to every filesystem path this script
#                               writes to or reads from (/usr/local/bin,
#                               /etc/systemd/system, /usr/share/keyrings,
#                               /etc/apt/sources.list.d, /etc/yum.repos.d).
#                               Not for production use.
set -eu

REPO="evertramos/ezy-shield"

# ROOT is a DESTDIR-style prefix used only by the CI test harness
# (scripts/get-sh-message-test.sh) to sandbox filesystem writes — it is
# empty (real root filesystem) in every real install.
ROOT="${EZYSHIELD_ROOT:-}"
INSTALL_DIR="${ROOT}/usr/local/bin"
SYSTEMD_DIR="${ROOT}/etc/systemd/system"
KEYRING_PATH="${ROOT}/usr/share/keyrings/ezyshield.gpg"
APT_SOURCE_PATH="${ROOT}/etc/apt/sources.list.d/ezyshield.list"
YUM_REPO_PATH="${ROOT}/etc/yum.repos.d/ezyshield.repo"
PACKAGES_BASE_URL="${EZYSHIELD_PACKAGES_BASE_URL:-https://packages.ezyshield.com}"

# Exact, fixed lists — every rm/systemctl action below iterates these known
# names, never a glob built from a variable or parsed output (issue #240
# security review §3: get.sh runs as root, so every filesystem mutation must
# be exact-path).
SCRIPT_BINARIES="ezyshield ezyshield-enforcer"
SCRIPT_UNITS="ezyshield.service ezyshield-enforcer.service"

# ── uninstall (script-install artifacts only) ───────────────────────────────
#
# Never touches package-managed files: it only ever removes the exact,
# hardcoded paths above under INSTALL_DIR/SYSTEMD_DIR, which are distinct
# from the package's /usr/bin and /usr/lib/systemd/system.
uninstall_script_install() {
  echo "Uninstalling EzyShield script-install artifacts (package-managed installs are never touched)..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop ezyshield ezyshield-enforcer >/dev/null 2>&1 || true
    systemctl disable ezyshield ezyshield-enforcer >/dev/null 2>&1 || true
  fi

  removed=0
  for b in $SCRIPT_BINARIES; do
    p="${INSTALL_DIR}/${b}"
    if [ -f "$p" ]; then
      rm -f "$p"
      echo "  removed ${p}"
      removed=1
    fi
  done
  for u in $SCRIPT_UNITS; do
    p="${SYSTEMD_DIR}/${u}"
    if [ -f "$p" ]; then
      rm -f "$p"
      echo "  removed ${p}"
      removed=1
    fi
  done

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  if [ "$removed" -eq 1 ]; then
    echo ""
    echo "Done. Package-managed files (/usr/bin, /usr/lib/systemd/system) were not touched."
    echo "Configuration in /etc/ezyshield was left in place -- remove manually if desired:"
    echo "  sudo rm -rf /etc/ezyshield"
  else
    echo "Nothing to remove -- no script-install binaries or unit overrides found."
  fi
}

# ── cleanup on transition to packages (issue #240) ──────────────────────────
#
# Detects a previous script install that would shadow a fresh package
# install: binaries in INSTALL_DIR (PATH precedence) and/or unit overrides in
# SYSTEMD_DIR whose ExecStart still points at INSTALL_DIR (systemd unit
# search-path precedence). Sets SHADOW_BINARIES / SHADOW_UNITS as
# space-separated exact paths for the caller.
SHADOW_BINARIES=""
SHADOW_UNITS=""

detect_shadowing_install() {
  SHADOW_BINARIES=""
  SHADOW_UNITS=""
  for b in $SCRIPT_BINARIES; do
    p="${INSTALL_DIR}/${b}"
    if [ -f "$p" ]; then
      SHADOW_BINARIES="${SHADOW_BINARIES}${SHADOW_BINARIES:+ }${p}"
    fi
  done
  for u in $SCRIPT_UNITS; do
    p="${SYSTEMD_DIR}/${u}"
    # Fixed-string containment check only -- never eval/interpolate the
    # ExecStart value itself into a command, just test whether it names
    # INSTALL_DIR (issue #240 security review §1/§3).
    if [ -f "$p" ] && grep -qF "ExecStart=${INSTALL_DIR}/" "$p" 2>/dev/null; then
      SHADOW_UNITS="${SHADOW_UNITS}${SHADOW_UNITS:+ }${p}"
    fi
  done
  [ -n "$SHADOW_BINARIES" ] || [ -n "$SHADOW_UNITS" ]
}

print_cleanup_commands() {
  echo ""
  echo "Found a previous script install that would shadow the package install:"
  for p in $SHADOW_BINARIES; do echo "    binary: $p"; done
  for p in $SHADOW_UNITS; do echo "    unit:   $p (ExecStart points at ${INSTALL_DIR})"; done
  echo ""
  echo "  Exact cleanup commands:"
  echo "    sudo systemctl stop ezyshield ezyshield-enforcer"
  for p in $SHADOW_BINARIES $SHADOW_UNITS; do
    echo "    sudo rm -f $p"
  done
  echo "    sudo systemctl daemon-reload"
  echo "    sudo systemctl enable --now ezyshield-enforcer ezyshield"
  echo ""
}

# maybe_cleanup_shadowing prints the exact cleanup commands whenever a
# shadowing script install is found, and only executes them when the operator
# opted in: EZYSHIELD_CLEANUP=1, or an interactive 'y' answer when stdin is a
# tty. Otherwise it leaves the host untouched (the operator runs the printed
# commands manually).
maybe_cleanup_shadowing() {
  if ! detect_shadowing_install; then
    return 0
  fi
  print_cleanup_commands

  do_cleanup=0
  if [ "${EZYSHIELD_CLEANUP:-0}" = "1" ]; then
    do_cleanup=1
  elif [ -t 0 ]; then
    printf '  Remove the shadowing script install now? [y/N] '
    read -r reply || reply=""
    case "$reply" in
      y | Y | yes | YES) do_cleanup=1 ;;
      *) do_cleanup=0 ;;
    esac
  fi

  if [ "$do_cleanup" -ne 1 ]; then
    echo "  Skipping cleanup -- run the commands above manually, or re-run with EZYSHIELD_CLEANUP=1."
    return 0
  fi

  echo "  Cleaning up the previous script install..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop ezyshield ezyshield-enforcer >/dev/null 2>&1 || true
  fi
  for p in $SHADOW_BINARIES $SHADOW_UNITS; do
    rm -f "$p"
  done
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now ezyshield-enforcer ezyshield >/dev/null 2>&1 || true
  fi
  echo "  Cleanup complete."
}

# ── package-first install (issue #240) ──────────────────────────────────────

# packages_repo_reachable does a cheap, bounded probe against the signing
# key URL -- the same asset the repo setup itself downloads next, so success
# here means the real setup will also be able to reach it.
packages_repo_reachable() {
  curl -sf --max-time 5 -o /dev/null "${PACKAGES_BASE_URL}/ezyshield.asc"
}

# install_via_packages sets up the apt/dnf repo (matching the documented
# manual steps in docs/content/en/getting-started/install.md, 'testing'
# suite pre-v0.1.0) and installs the ezyshield package. Returns non-zero on
# any failure so the caller can fall back to the binary install.
install_via_packages() {
  pkg_mgr="$1"
  echo "Package manager detected (${pkg_mgr}) -- setting up the EzyShield repository..."

  case "$pkg_mgr" in
    apt)
      mkdir -p "$(dirname "$KEYRING_PATH")" "$(dirname "$APT_SOURCE_PATH")"
      if ! curl -fsSL "${PACKAGES_BASE_URL}/ezyshield.asc" | gpg --dearmor -o "$KEYRING_PATH"; then
        echo "Warning: failed to import the EzyShield signing key." >&2
        return 1
      fi
      echo "deb [signed-by=${KEYRING_PATH}] ${PACKAGES_BASE_URL}/apt testing main" >"$APT_SOURCE_PATH"
      apt-get update -qq && apt-get install -y ezyshield
      ;;
    dnf | yum)
      mkdir -p "$(dirname "$YUM_REPO_PATH")"
      cat >"$YUM_REPO_PATH" <<EOF
[ezyshield]
name=EzyShield
baseurl=${PACKAGES_BASE_URL}/rpm/testing/\$basearch
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=${PACKAGES_BASE_URL}/ezyshield.asc
EOF
      "$pkg_mgr" install -y ezyshield
      ;;
    *)
      return 1
      ;;
  esac
}

# ── argument parsing ─────────────────────────────────────────────────────────

UNINSTALL="${EZYSHIELD_UNINSTALL:-0}"
for arg in "$@"; do
  case "$arg" in
    --uninstall) UNINSTALL=1 ;;
    --help | -h)
      echo "Usage: curl -sfL https://get.ezyshield.com | sudo sh"
      echo "       curl -sfL https://get.ezyshield.com | sudo sh -s -- --uninstall"
      exit 0
      ;;
  esac
done

if [ "$UNINSTALL" = "1" ]; then
  uninstall_script_install
  exit 0
fi

# ── platform detection ───────────────────────────────────────────────────────

ARCH=$(uname -m)
case "$ARCH" in
  x86_64 | amd64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *)
    echo "Error: unsupported architecture: $ARCH"
    exit 1
    ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
  echo "Error: EzyShield only supports Linux (got: $OS)"
  exit 1
fi

SUFFIX="${OS}-${ARCH}"

# ── install-method selection ─────────────────────────────────────────────────

PKG_MGR=""
if command -v apt-get >/dev/null 2>&1; then
  PKG_MGR="apt"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
  PKG_MGR="yum"
fi

METHOD="${EZYSHIELD_METHOD:-auto}"
case "$METHOD" in
  auto | packages | binary) ;;
  *)
    echo "Error: EZYSHIELD_METHOD must be 'auto', 'packages', or 'binary' (got: $METHOD)"
    exit 1
    ;;
esac

USE_PACKAGES=0
if [ -n "${EZYSHIELD_BASE_URL:-}" ]; then
  : # custom mirror always wins -- air-gapped, binary mode
elif [ "$METHOD" = "binary" ]; then
  if [ -n "$PKG_MGR" ]; then
    echo "Note: native .deb/.rpm packages are available for this host (EZYSHIELD_METHOD=binary was requested) --"
    echo "      see the install docs: https://github.com/${REPO}#install"
    echo ""
  fi
elif [ -z "$PKG_MGR" ]; then
  : # no deb/rpm tooling on this host -- binary mode
else
  # auto or packages: try the repo, fall back loudly on any failure so the
  # install still completes.
  if packages_repo_reachable; then
    USE_PACKAGES=1
  else
    echo ""
    echo "Warning: could not reach the EzyShield package repository (${PACKAGES_BASE_URL})."
    echo "         Falling back to the raw-binary install. Package setup docs:"
    echo "         https://github.com/${REPO}#install"
    echo ""
  fi
fi

if [ "$USE_PACKAGES" = "1" ]; then
  maybe_cleanup_shadowing
  if install_via_packages "$PKG_MGR"; then
    echo ""
    echo "✅ EzyShield installed via ${PKG_MGR}."
    echo ""
    echo "Next steps:"
    echo "  sudo ezyshield init    # interactive setup wizard"
    echo ""
    exit 0
  fi
  echo ""
  echo "Warning: package install failed -- falling back to the raw-binary install."
  echo ""
fi

# ── binary-mode install (fallback / explicit / air-gapped / no tooling) ─────

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
    *)
      echo "Error: EZYSHIELD_VERSION must start with 'v' (got: $VERSION)"
      exit 1
      ;;
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
mkdir -p "$INSTALL_DIR"
install -m 755 ezyshield "${INSTALL_DIR}/ezyshield"
install -m 755 ezyshield-enforcer "${INSTALL_DIR}/ezyshield-enforcer"

echo ""
echo "✅ EzyShield ${VERSION} installed to ${INSTALL_DIR}/"
echo ""
echo "Next steps:"
echo "  sudo ezyshield init    # interactive setup wizard"
echo ""
