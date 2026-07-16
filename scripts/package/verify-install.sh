#!/usr/bin/env bash
#
# verify-install.sh — install EzyShield from the PUBLISHED package
# repositories (packages.ezyshield.com) exactly the way the install guide
# tells a real user to, and verify the whole chain: the GPG key fingerprint
# pinned in the docs, the signed repository metadata, the package install,
# and the promises the guide makes (service user, units present, nothing
# enabled or started).
#
# WHY (issue #165): publish-repos.yaml uploads packages and signed metadata
# to R2, but nothing in CI ever consumed them. A broken Release file, a
# wrong or expired key, or docs drifting from the real repo layout would
# only surface as a user bug report. The `packages` job in ci.yaml covers
# the locally-built snapshot .deb/.rpm; this script covers the published,
# signed path end to end — including a NEGATIVE test proving the signature
# is required, not merely present.
#
# Runs INSIDE the target distro (a container in CI, as root); detects
# apt vs dnf. Debian/Ubuntu and RHEL-family are supported.
#
# Usage:
#   verify-install.sh --suite <stable|testing> [--expect-version vX.Y.Z]
#                     [--allow-missing-suite]
#
#   --suite                which documented suite to install from
#   --expect-version       release tag; `ezyshield version` must match it
#                          (retries briefly — CDN metadata may lag a publish)
#   --allow-missing-suite  exit 0 with a notice when the suite has never
#                          been published (scheduled runs before v0.1.0)
#
# Local run (same legs as CI):
#   docker run --rm -v "$PWD:/src:ro" debian:12 \
#     /src/scripts/package/verify-install.sh --suite testing
#   docker run --rm -v "$PWD:/src:ro" rockylinux:9 \
#     /src/scripts/package/verify-install.sh --suite testing
#
set -euo pipefail

BASE_URL="https://packages.ezyshield.com"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_DOC="$REPO_ROOT/docs/content/en/getting-started/install.md"
KEYRING=/usr/share/keyrings/ezyshield.gpg
APT_LIST=/etc/apt/sources.list.d/ezyshield.list
VERSION_RETRIES=5          # publish → CDN visibility can lag; bounded retry
VERSION_RETRY_DELAY=45

SUITE=""
EXPECT=""
ALLOW_MISSING=0

pass=0; fail=0
ROWS=""
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass+1)); ROWS="${ROWS}| $1 | ✅ |
"; }
bad()  { printf '  \033[31m✗ %s\033[0m\n' "$1"; fail=$((fail+1)); ROWS="${ROWS}| $1 | ❌ |
"; }
info() { printf '\033[36m▸ %s\033[0m\n' "$1"; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }

# check "<description>" <command...> — runs the command, records pass/fail.
check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}

usage() { sed -n '2,37p' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --suite)               SUITE="${2:?--suite needs a value}"; shift ;;
    --expect-version)      EXPECT="${2:?--expect-version needs a value}"; shift ;;
    --allow-missing-suite) ALLOW_MISSING=1 ;;
    -h|--help)             usage ;;
    *) echo "unknown argument: $1" >&2; usage 2 ;;
  esac
  shift
done

case "$SUITE" in
  stable|testing) ;;
  "") die "--suite is required (stable | testing)" ;;
  *)  die "invalid suite '$SUITE' (stable | testing)" ;;
esac
if [ -n "$EXPECT" ] && [ "${EXPECT#v}" = "$EXPECT" ]; then
  die "--expect-version must be a release tag starting with 'v' (got '$EXPECT')"
fi
[ "$(id -u)" -eq 0 ] || die "must run as root (use a throwaway container)"
[ -f "$INSTALL_DOC" ] || die "install guide not found at $INSTALL_DOC"

# The docs are the contract: the fingerprint asserted below is the one a
# user is told to verify, grep-extracted so doc drift fails this gate.
DOC_FPR="$(grep -Eo '([0-9A-F]{4}[[:space:]]+){9}[0-9A-F]{4}' "$INSTALL_DOC" \
  | head -n1 | tr -d '[:space:]')"
[ "${#DOC_FPR}" -eq 40 ] || die "could not extract the signing-key fingerprint from $INSTALL_DOC"

if command -v apt-get >/dev/null 2>&1; then
  FAMILY=apt
elif command -v dnf >/dev/null 2>&1; then
  FAMILY=dnf
else
  die "unsupported distro: neither apt-get nor dnf found"
fi

# shellcheck disable=SC1091 # /etc/os-release is provided by the distro
DISTRO="$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" )"
info "verify-install: $DISTRO / $FAMILY / suite=$SUITE${EXPECT:+ / expect=$EXPECT}"

# --- Prerequisites (environment setup, not part of the documented flow) ---
if [ "$FAMILY" = apt ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -qq update >/dev/null
  apt-get -qq install -y curl ca-certificates gnupg >/dev/null
else
  command -v curl >/dev/null 2>&1 || dnf -q -y install curl >/dev/null
  command -v gpg  >/dev/null 2>&1 || dnf -q -y install gnupg2 >/dev/null
fi

# --- Suite published? ---
ARCH="$(uname -m)"
if [ "$FAMILY" = apt ]; then
  PROBE_URL="$BASE_URL/apt/dists/$SUITE/Release"
else
  PROBE_URL="$BASE_URL/rpm/$SUITE/$ARCH/repodata/repomd.xml"
fi
if ! curl -fsI "$PROBE_URL" >/dev/null 2>&1; then
  if [ "$ALLOW_MISSING" -eq 1 ]; then
    info "suite '$SUITE' is not published yet ($PROBE_URL absent) — skipping by request"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      {
        echo "### 🔏 Verify install — $DISTRO / \`$SUITE\`"
        echo ""
        echo "_Suite \`$SUITE\` has never been published — nothing to verify (expected until the first stable release)._"
      } >> "$GITHUB_STEP_SUMMARY"
    fi
    exit 0
  fi
  die "suite '$SUITE' not found upstream ($PROBE_URL)"
fi

# --- Negative test: a WRONG key must make the package manager refuse ---
# Proves signature verification is enforced, not merely configured. Runs
# before the real install so the package-manager state is still clean.
NEG_HOME="$(mktemp -d)"
NEG_ASC="$(mktemp --suffix=.asc)"
NEG_GPG=/usr/share/keyrings/ezyshield-negative-test.gpg
NEG_LIST=/etc/apt/sources.list.d/ezyshield-negative-test.list
NEG_REPO=/etc/yum.repos.d/ezyshield-negative-test.repo
cleanup_negative() {
  rm -rf "$NEG_HOME" "$NEG_ASC" "$NEG_GPG" "$NEG_LIST" "$NEG_REPO"
}
trap cleanup_negative EXIT

info "negative test: repository configured with a key that is NOT ours"
gpg --homedir "$NEG_HOME" --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'EzyShield negative test (wrong key) <wrong-key@example.invalid>' \
  default default never >/dev/null 2>&1

if [ "$FAMILY" = apt ]; then
  gpg --homedir "$NEG_HOME" --export > "$NEG_GPG"
  echo "deb [signed-by=$NEG_GPG] $BASE_URL/apt $SUITE main" > "$NEG_LIST"
  neg_out="$(apt-get update 2>&1)" && neg_rc=0 || neg_rc=$?
  if [ "$neg_rc" -ne 0 ] && printf '%s' "$neg_out" | grep -Eq 'NO_PUBKEY|is not signed|not.*verified'; then
    ok "apt refuses repository metadata signed by an unknown key"
  else
    bad "apt ACCEPTED metadata despite wrong signing key (rc=$neg_rc)"
  fi
  rm -f "$NEG_LIST" /var/lib/apt/lists/*packages.ezyshield.com*
else
  gpg --homedir "$NEG_HOME" --armor --export > "$NEG_ASC"
  cat > "$NEG_REPO" <<EOF
[ezyshield-negative-test]
name=EzyShield negative test (wrong key)
baseurl=$BASE_URL/rpm/$SUITE/\$basearch
enabled=1
gpgcheck=0
repo_gpgcheck=1
skip_if_unavailable=0
gpgkey=file://$NEG_ASC
EOF
  if dnf -q -y makecache --disablerepo='*' --enablerepo=ezyshield-negative-test >/dev/null 2>&1; then
    bad "dnf ACCEPTED repository metadata despite wrong signing key"
  else
    ok "dnf refuses repository metadata signed by an unknown key"
  fi
  rm -f "$NEG_REPO"
  dnf -q clean all >/dev/null 2>&1 || true
fi

# --- Positive path: the documented install, verbatim (minus sudo) ---
info "documented install flow ($FAMILY, suite=$SUITE)"
if [ "$FAMILY" = apt ]; then
  curl -fsSL "$BASE_URL/ezyshield.asc" | gpg --dearmor --yes -o "$KEYRING"
  GOT_FPR="$(gpg --show-keys --with-colons "$KEYRING" | awk -F: '/^fpr/{print $10; exit}')"
else
  curl -fsSL "$BASE_URL/ezyshield.asc" -o /tmp/ezyshield.asc
  GOT_FPR="$(gpg --show-keys --with-colons /tmp/ezyshield.asc | awk -F: '/^fpr/{print $10; exit}')"
fi
# A fingerprint mismatch is fatal, not a counted failure: installing a
# package signed by an unexpected key is exactly what this gate exists to
# prevent, so nothing after this point would be trustworthy.
if [ "$GOT_FPR" = "$DOC_FPR" ]; then
  ok "signing-key fingerprint matches the one pinned in install.md ($DOC_FPR)"
else
  bad "fingerprint mismatch: docs pin $DOC_FPR, key at $BASE_URL/ezyshield.asc is ${GOT_FPR:-<none>}"
  die "aborting before install — the published key is not the documented one"
fi

if [ "$FAMILY" = apt ]; then
  echo "deb [signed-by=$KEYRING] $BASE_URL/apt $SUITE main" > "$APT_LIST"
else
  cat > /etc/yum.repos.d/ezyshield.repo <<EOF
[ezyshield]
name=EzyShield
baseurl=$BASE_URL/rpm/$SUITE/\$basearch
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=$BASE_URL/ezyshield.asc
EOF
fi

refresh_and_install() {
  if [ "$FAMILY" = apt ]; then
    apt-get -qq update >/dev/null
    apt-get -qq install -y ezyshield >/dev/null
  else
    dnf -q clean expire-cache >/dev/null 2>&1 || true
    dnf -q -y install ezyshield >/dev/null
  fi
}

version_matches() {
  [ -z "$EXPECT" ] && return 0
  # deb encodes prereleases with '~' (0.1.0~rc.19) while the tag and the
  # binary use '-' — normalize both before comparing.
  printf '%s' "$1" | tr '~' '-' | grep -qF "$(printf '%s' "${EXPECT#v}" | tr '~' '-')"
}

attempt=1
while :; do
  refresh_and_install
  GOT_VERSION="$(ezyshield version 2>/dev/null || true)"
  version_matches "$GOT_VERSION" && break
  if [ "$attempt" -ge "$VERSION_RETRIES" ]; then break; fi
  info "expected $EXPECT not visible yet (got: ${GOT_VERSION:-nothing}) — CDN metadata may lag; retry $attempt/$VERSION_RETRIES in ${VERSION_RETRY_DELAY}s"
  sleep "$VERSION_RETRY_DELAY"
  attempt=$((attempt+1))
done

check "package installs from the signed '$SUITE' repository" test -x /usr/bin/ezyshield
check "enforcer binary installed at /usr/bin/ezyshield-enforcer" test -x /usr/bin/ezyshield-enforcer
if [ -n "$EXPECT" ]; then
  if version_matches "$GOT_VERSION"; then
    ok "ezyshield version matches $EXPECT ($GOT_VERSION)"
  else
    bad "version mismatch: expected $EXPECT, got '${GOT_VERSION:-nothing}'"
  fi
else
  info "installed: ${GOT_VERSION:-<version unavailable>} (no --expect-version given)"
fi

# --- Promises install.md makes about the package ---
check "service user 'ezyshield' created" getent passwd ezyshield
check "service group 'ezyshield' created" getent group ezyshield
check "/etc/ezyshield is 750 root:ezyshield" \
  test "$(stat -c '%a %U:%G' /etc/ezyshield 2>/dev/null)" = "750 root:ezyshield"
check "/var/lib/ezyshield is 750 ezyshield:ezyshield" \
  test "$(stat -c '%a %U:%G' /var/lib/ezyshield 2>/dev/null)" = "750 ezyshield:ezyshield"
check "systemd unit ezyshield.service shipped" test -f /usr/lib/systemd/system/ezyshield.service
check "systemd unit ezyshield-enforcer.service shipped" test -f /usr/lib/systemd/system/ezyshield-enforcer.service
if find /etc/systemd/system -name 'ezyshield*' 2>/dev/null | grep -q .; then
  bad "package enabled a systemd unit — install.md promises it never does"
else
  ok "no unit enabled or started (as documented)"
fi

# --- Summary ---
echo
info "result: $pass passed, $fail failed ($DISTRO, suite=$SUITE)"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### 🔏 Verify install — $DISTRO / \`$SUITE\`"
    echo "_Installs EzyShield from the published signed repositories exactly as install.md documents — key fingerprint pinned by the docs, wrong-key negative test, package promises._"
    echo ""
    echo "| Check | Result |"
    echo "|---|---|"
    printf '%s' "$ROWS"
    echo ""
    echo "**Installed:** \`${GOT_VERSION:-n/a}\`"
  } >> "$GITHUB_STEP_SUMMARY"
fi
[ "$fail" -eq 0 ]
