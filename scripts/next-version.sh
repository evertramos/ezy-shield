#!/usr/bin/env bash
#
# next-version.sh — single source of truth for release tag calculation.
#
# WHY: the release workflow used to compute the next RC inline and only ever
# incremented the newest -rc.N tag it could find. Once v0.1.0 (final) shipped,
# the next dispatched RC came out as v0.1.0-rc.29 — an RC *behind* its own
# released base. An RC series is closed the moment its base version has a
# final tag; the next RC must open a new series computed from the latest
# stable release (next minor → v0.2.0-rc.1 by default), and the operator may
# aim the series at a different release with rc_base (major → v1.0.0-rc.1).
#
# Usage: next-version.sh <patch|minor|major|rc> [auto|patch|minor|major]
#   $1  bump     — stable bump kind, or "rc" for a prerelease tag
#   $2  rc_base  — RC only: which release the RC series targets.
#                  auto (default): continue the open series while its base is
#                  unreleased; otherwise start <next minor>-rc.1.
#                  patch|minor|major: target that bump of the latest stable;
#                  an existing series for the same base is continued.
#
# Prints the next tag on stdout. Read-only: the only input is `git tag`.

set -euo pipefail

BUMP="${1:?usage: next-version.sh <patch|minor|major|rc> [auto|patch|minor|major]}"
RC_BASE="${2:-auto}"

latest_final() {
  git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true
}

latest_rc() {
  git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$' | head -1 || true
}

# bump_of vX.Y.Z <major|minor|patch> → the bumped vX'.Y'.Z'
bump_of() {
  local v="${1#v}" kind="$2" major minor patch
  IFS=. read -r major minor patch <<<"$v"
  case "$kind" in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
    *) echo "next-version.sh: invalid bump kind '$kind'" >&2; exit 2 ;;
  esac
  echo "v${major}.${minor}.${patch}"
}

case "$BUMP" in
  patch | minor | major)
    LATEST="$(latest_final)"
    bump_of "${LATEST:-v0.0.0}" "$BUMP"
    ;;
  rc)
    case "$RC_BASE" in
      auto | patch | minor | major) ;;
      *)
        echo "next-version.sh: invalid rc_base '$RC_BASE' (want auto|patch|minor|major)" >&2
        exit 2
        ;;
    esac
    LATEST="$(latest_final)"
    LATEST="${LATEST:-v0.0.0}"
    LATEST_RC="$(latest_rc)"

    if [ "$RC_BASE" = "auto" ]; then
      if [ -n "$LATEST_RC" ]; then
        RC_SERIES_BASE="${LATEST_RC%-rc.*}"
        # The series is open only while its base has no final tag.
        if [ -z "$(git tag -l "$RC_SERIES_BASE")" ]; then
          RC_NUM="${LATEST_RC##*-rc.}"
          echo "${RC_SERIES_BASE}-rc.$((RC_NUM + 1))"
          exit 0
        fi
      fi
      # No open series: an rc rehearses the next minor by default.
      echo "$(bump_of "$LATEST" minor)-rc.1"
    else
      TARGET="$(bump_of "$LATEST" "$RC_BASE")"
      if [ -n "$LATEST_RC" ] && [ "${LATEST_RC%-rc.*}" = "$TARGET" ]; then
        RC_NUM="${LATEST_RC##*-rc.}"
        echo "${TARGET}-rc.$((RC_NUM + 1))"
      else
        echo "${TARGET}-rc.1"
      fi
    fi
    ;;
  *)
    echo "next-version.sh: invalid bump '$BUMP' (want patch|minor|major|rc)" >&2
    exit 2
    ;;
esac
