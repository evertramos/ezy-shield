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
# still completes). Exception: if the host ALREADY has a package-managed
# EzyShield install, every binary-mode path refuses (EZYSHIELD_FORCE_SCRIPT=1
# overrides) — installing to /usr/local/bin there would shadow the package.
#
# Supply-chain authentication (issue #17): on the GitHub-release paths
# (default, EZYSHIELD_VERSION, --dev) this script verifies checksums.txt's
# cosign keyless signature against the pinned release-workflow identity
# before trusting it, whenever cosign is installed on the host — see
# docs/content/en/security/verifying-releases.md. Without cosign it warns
# (not fails) and falls back to SHA-256 over TLS. Releases that predate
# signing have no .sig/.pem assets; that also degrades with a warning.
#
# Flags (after `sh -s --`):
#   --dev        Install the newest release INCLUDING prereleases (release
#                candidates). Same trust chain as the default path — only the
#                version selection differs. Binary mode.
#   --local      Required to use EZYSHIELD_BASE_URL (see below). Must be
#                combined with EZYSHIELD_LOCAL_ACK=1.
#   --uninstall  Remove script-install artifacts and exit.
#
# Environment variables:
#   EZYSHIELD_VERSION          Install a specific release (e.g., v0.1.0-rc.21).
#                               Must start with 'v'. Binary mode only.
#   EZYSHIELD_DEV              Set to 1 — same as --dev.
#   EZYSHIELD_LOCAL            Set to 1 — same as --local.
#   EZYSHIELD_LOCAL_ACK        Must be set to 1 together with --local. The
#                               deliberate friction exists because a custom
#                               mirror is NOT authenticated: checksums.txt
#                               comes from the same mirror as the binaries,
#                               so verification only defends against transfer
#                               corruption, not a malicious mirror.
#   EZYSHIELD_BASE_URL         Install from a custom mirror (air-gapped
#                               installs, the QEMU dev harness). Requires
#                               --local AND EZYSHIELD_LOCAL_ACK=1. Overrides
#                               version selection and forces binary mode.
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
#   EZYSHIELD_FORCE_SCRIPT       Set to 1 to force a raw-binary install onto a
#                               host that already has a package-managed
#                               EzyShield install (/usr/bin/ezyshield owned by
#                               dpkg/rpm). Without it, binary mode refuses on
#                               such hosts: /usr/local/bin binaries would
#                               shadow the package install (issue #240).
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

# package_owned_install reports whether this host already runs a
# package-managed EzyShield: /usr/bin/ezyshield exists AND dpkg/rpm confirms
# a package owns it. When neither dpkg nor rpm is available to ask, the
# file's presence in ${ROOT}/usr/bin is treated as package-managed (nothing
# else installs there; refusing is the safe default). The dpkg/rpm queries
# are read-only and their output is never parsed or interpolated — only the
# exit code is used (issue #240 security review §1).
package_owned_install() {
  [ -f "${ROOT}/usr/bin/ezyshield" ] || return 1
  have_pkg_query=0
  if command -v dpkg >/dev/null 2>&1; then
    have_pkg_query=1
    if dpkg -S /usr/bin/ezyshield >/dev/null 2>&1; then
      return 0
    fi
  fi
  if command -v rpm >/dev/null 2>&1; then
    have_pkg_query=1
    if rpm -qf /usr/bin/ezyshield >/dev/null 2>&1; then
      return 0
    fi
  fi
  # /usr/bin/ezyshield exists but neither dpkg nor rpm was available to
  # confirm ownership: treat it as package-managed (refuse). When a tool
  # WAS available and answered "not owned", don't refuse — an unowned
  # /usr/bin/ezyshield is a manual copy, not a package install.
  [ "$have_pkg_query" -eq 0 ]
}

# refuse_binary_over_package prints the refusal message (or the
# EZYSHIELD_FORCE_SCRIPT warning) when a package-managed install exists.
# Called at the top of every binary-mode path, BEFORE any download.
refuse_binary_over_package() {
  if ! package_owned_install; then
    return 0
  fi
  if [ "${EZYSHIELD_FORCE_SCRIPT:-0}" = "1" ]; then
    echo ""
    echo "Warning: EZYSHIELD_FORCE_SCRIPT=1 — installing script binaries to ${INSTALL_DIR}"
    echo "         on a host with a package-managed EzyShield install. These binaries"
    echo "         WILL shadow the package's /usr/bin ones (PATH order); 'ezyshield doctor'"
    echo "         will FAIL on this until you remove one of the two installs."
    echo ""
    return 0
  fi
  echo ""
  echo "Error: this host already has a package-managed EzyShield install"
  echo "(/usr/bin/ezyshield). Installing script binaries to ${INSTALL_DIR} would"
  echo "shadow it via PATH order — the exact failure 'ezyshield doctor' flags."
  echo ""
  echo "Upgrade with your package manager instead:"
  echo "  # Debian / Ubuntu"
  echo "  sudo apt update && sudo apt install --only-upgrade ezyshield"
  echo "  # RHEL / Rocky / Alma"
  echo "  sudo dnf upgrade ezyshield"
  echo ""
  echo "To force a script install anyway (it will shadow the package install):"
  echo "  ... | sudo EZYSHIELD_FORCE_SCRIPT=1 sh"
  echo ""
  exit 1
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
DEV_MODE="${EZYSHIELD_DEV:-0}"
LOCAL_MODE="${EZYSHIELD_LOCAL:-0}"
for arg in "$@"; do
  case "$arg" in
    --uninstall) UNINSTALL=1 ;;
    --dev) DEV_MODE=1 ;;
    --local) LOCAL_MODE=1 ;;
    --help | -h)
      echo "Usage: curl -sfL https://get.ezyshield.com | sudo sh"
      echo "       curl -sfL https://get.ezyshield.com | sudo sh -s -- --dev        # newest prerelease"
      echo "       curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_LOCAL_ACK=1 EZYSHIELD_BASE_URL=<mirror> sh -s -- --local"
      echo "       curl -sfL https://get.ezyshield.com | sudo sh -s -- --uninstall"
      exit 0
      ;;
  esac
done

if [ "$UNINSTALL" = "1" ]; then
  uninstall_script_install
  exit 0
fi

# ── --local gating (issue #17) ──────────────────────────────────────────────
#
# A custom mirror is the one install path with NO source authentication:
# checksums.txt comes from the same mirror as the binaries, so the SHA-256
# comparison only defends against transfer corruption — a malicious mirror
# passes it trivially. Gate it behind an explicit flag + ack so the line
# cannot be pasted into production by accident.
if [ -n "${EZYSHIELD_BASE_URL:-}" ] && [ "$LOCAL_MODE" != "1" ]; then
  echo "Error: EZYSHIELD_BASE_URL now requires the explicit --local flag (plus EZYSHIELD_LOCAL_ACK=1):"
  echo ""
  echo "  curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_LOCAL_ACK=1 EZYSHIELD_BASE_URL=${EZYSHIELD_BASE_URL} sh -s -- --local"
  echo ""
  echo "This install path does not authenticate the source — use it only for"
  echo "trusted mirrors, air-gapped installs, or the QEMU dev harness."
  exit 1
fi
if [ "$LOCAL_MODE" = "1" ]; then
  if [ -z "${EZYSHIELD_BASE_URL:-}" ]; then
    echo "Error: --local requires EZYSHIELD_BASE_URL to point at the mirror to install from."
    exit 1
  fi
  if [ "${EZYSHIELD_LOCAL_ACK:-0}" != "1" ]; then
    echo "Error: --local additionally requires EZYSHIELD_LOCAL_ACK=1 in the environment."
    echo ""
    echo "This acknowledges that a mirror install does NOT authenticate the source:"
    echo "checksums.txt is fetched from the same mirror as the binaries, so the"
    echo "verification only defends against transfer corruption — not a malicious"
    echo "or compromised mirror. Use only trusted mirrors or the QEMU dev harness."
    exit 1
  fi
  if [ "$DEV_MODE" = "1" ]; then
    echo "Error: --dev and --local are mutually exclusive (--local installs whatever the mirror serves)."
    exit 1
  fi
  echo ""
  echo "WARNING: --local install from ${EZYSHIELD_BASE_URL}"
  echo "         This path does not authenticate the source. Binaries and checksums"
  echo "         come from the same mirror, so a compromised mirror passes every"
  echo "         check. Use only for trusted mirrors or the QEMU dev harness."
  echo ""
fi
if [ "$DEV_MODE" = "1" ] && [ -n "${EZYSHIELD_VERSION:-}" ]; then
  echo "Error: --dev and EZYSHIELD_VERSION are mutually exclusive (pick one way to choose the version)."
  exit 1
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
elif [ "$DEV_MODE" = "1" ]; then
  # --dev pins the newest GitHub prerelease — binary mode by design. The
  # package-channel equivalent is the 'testing' suite, which apt/dnf hosts
  # already get by default pre-v0.1.0.
  if [ -n "$PKG_MGR" ]; then
    echo "Note: --dev installs the newest prerelease binaries from GitHub Releases."
    echo "      The package-repo equivalent is the 'testing' suite -- see the install docs."
    echo ""
  fi
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

# Guard (issue #240, original acceptance criterion b): never drop script
# binaries onto a host that already runs the packages — that recreates the
# shadowing bug in reverse. Applies to EVERY binary-mode path, including the
# automatic fallback above and EZYSHIELD_BASE_URL mirrors; runs before any
# download. EZYSHIELD_FORCE_SCRIPT=1 overrides with a loud warning.
refuse_binary_over_package

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
elif [ "$DEV_MODE" = "1" ]; then
  # --dev: newest release INCLUDING prereleases. Same trust chain as the
  # default path (TLS + cosign verification below) — only the version
  # selection differs.
  echo "Fetching newest prerelease..."
  API_BASE="${EZYSHIELD_API_BASE_URL:-https://api.github.com}"
  VERSION=$(curl -sfL "${API_BASE}/repos/${REPO}/releases?per_page=1" 2>/dev/null | grep '"tag_name"' | head -n1 | sed 's/.*"tag_name": *"//;s/".*//')
  # Same trust rule as the RC hint on the 404 path: the tag is API response
  # data that ends up in URLs and output — accept only plain release tags.
  case "$VERSION" in
    v*) case "$VERSION" in *[!A-Za-z0-9.-]*) VERSION="" ;; esac ;;
    *) VERSION="" ;;
  esac
  if [ -z "$VERSION" ]; then
    echo "Error: could not resolve the newest prerelease from the GitHub API."
    echo "Available releases: https://github.com/${REPO}/releases"
    exit 1
  fi
  case "$VERSION" in
    *-*) echo "Note: ${VERSION} is a prerelease (that is what --dev selects)." ;;
  esac
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
  echo "Installing EzyShield ${VERSION} (${SUFFIX})..."
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

# verify_checksums_signature authenticates checksums.txt before anything
# trusts it (issue #17 / #100). GitHub-release paths only — --local skips it
# (the loud warning above already states that path is unauthenticated).
#
# Verification proves checksums.txt was produced by THIS repository's
# release.yaml workflow on GitHub's infrastructure (cosign keyless, Sigstore
# transparency log). Identity is pinned to repo + workflow file; the ref
# part accepts both release trigger paths (tag push, or workflow_dispatch
# from main/dev). Degrades with a warning — never a failure — when cosign is
# not installed or the release predates signing; FAILS HARD when a signature
# exists but does not verify.
verify_checksums_signature() {
  if [ "$LOCAL_MODE" = "1" ]; then
    return 0
  fi
  if ! command -v cosign >/dev/null 2>&1; then
    echo "Note: cosign not found -- skipping signature verification of checksums.txt."
    echo "      Integrity is still checked via SHA-256 over TLS to github.com. For"
    echo "      cryptographic provenance verification, install cosign:"
    echo "      https://docs.sigstore.dev/cosign/system_config/installation/"
    return 0
  fi
  if ! curl -sfL "${BASE_URL}/checksums.txt.sig" -o "${TMP}/checksums.txt.sig" ||
    ! curl -sfL "${BASE_URL}/checksums.txt.pem" -o "${TMP}/checksums.txt.pem"; then
    echo "Warning: release ${VERSION} has no cosign signature assets (it predates"
    echo "         signed releases). Integrity rests on SHA-256 over TLS to github.com."
    return 0
  fi
  echo "Verifying checksums.txt signature (cosign keyless)..."
  if ! cosign verify-blob \
    --certificate "${TMP}/checksums.txt.pem" \
    --signature "${TMP}/checksums.txt.sig" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --certificate-identity-regexp '^https://github\.com/evertramos/ezy-shield/\.github/workflows/release\.yaml@refs/(tags/v[0-9][^ ]*|heads/(main|dev))$' \
    "${TMP}/checksums.txt" >/dev/null 2>&1; then
    echo "Error: cosign signature verification FAILED for checksums.txt."
    echo "The release assets may have been tampered with. Refusing to install."
    echo "Manual verification steps: https://github.com/${REPO} -> docs -> security/verifying-releases"
    exit 1
  fi
  echo "Signature verified: checksums.txt was built by the ${REPO} release workflow."
}

# Download binaries
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if ! curl -sfL "${BASE_URL}/checksums.txt" -o "${TMP}/checksums.txt"; then
  echo "Error: checksums.txt not found at ${BASE_URL}/checksums.txt"
  echo "The release ${VERSION} may not have pre-built binaries yet."
  echo "Available releases: https://github.com/${REPO}/releases"
  exit 1
fi

verify_checksums_signature
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
