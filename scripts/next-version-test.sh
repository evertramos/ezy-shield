#!/usr/bin/env bash
#
# next-version-test.sh — regression test for scripts/next-version.sh.
#
# WHY: after v0.1.0 (final) shipped, the release workflow's inline RC logic
# still produced v0.1.0-rc.29 — it only ever incremented the newest -rc.N
# tag, never noticing the series' base had already been released. These
# tests pin the contract: a released base closes its RC series (auto moves
# to <next minor>-rc.1), and rc_base lets the operator aim the series at a
# patch/minor/major of the latest stable instead.
#
# Each scenario runs in its own throwaway git repo under mktemp — fully
# offline, deterministic, no network and no writes outside $TMP.
#
# Usage: bash scripts/next-version-test.sh
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/next-version.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAIL=0
N=0

# check <expected> <tag...|none> -- <script args...>
check() {
  local expected="$1"
  shift
  local tags=()
  while [ "$1" != "--" ]; do
    tags+=("$1")
    shift
  done
  shift
  local repo="$TMP/r$N"
  N=$((N + 1))
  git init -q "$repo"
  git -C "$repo" -c user.email=t@t -c user.name=t commit -q --allow-empty -m x
  local t
  for t in "${tags[@]}"; do
    [ "$t" = "none" ] || git -C "$repo" tag "$t"
  done
  local got rc=0
  got="$(cd "$repo" && bash "$SCRIPT" "$@" 2>/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    got="(exit $rc)"
  fi
  if [ "$got" = "$expected" ]; then
    echo "ok   [${tags[*]}] $* -> $got"
  else
    echo "FAIL [${tags[*]}] $* -> got '$got', want '$expected'"
    FAIL=1
  fi
}

# First RC ever: empty repo rehearses the first minor.
check v0.1.0-rc.1 none -- rc

# An open series (base unreleased) keeps incrementing.
check v0.1.0-rc.3 v0.1.0-rc.2 -- rc

# THE BUG: base released → series closed → next minor, rc.1 (not rc.29).
check v0.2.0-rc.1 v0.1.0 v0.1.0-rc.28 -- rc
check v0.2.0-rc.1 v0.1.0 v0.1.0-rc.28 -- rc auto

# Operator-chosen series target.
check v1.0.0-rc.1 v0.1.0 v0.1.0-rc.28 -- rc major
check v1.0.0-rc.2 v0.1.0 v1.0.0-rc.1 -- rc major
check v0.2.0-rc.1 v0.1.0 v1.0.0-rc.2 -- rc minor
check v0.1.1-rc.1 v0.1.0 -- rc patch

# Stale closed series alongside a newer open one: continue the open one.
check v0.2.0-rc.4 v0.1.0 v0.1.0-rc.29 v0.2.0-rc.3 -- rc

# rc numbers compare numerically (rc.9 → rc.10, not lexically).
check v0.2.0-rc.10 v0.1.0 v0.2.0-rc.9 -- rc

# Series closed by its own final release.
check v0.3.0-rc.1 v0.2.0 v0.2.0-rc.5 -- rc

# Stable bumps, with rc tags present as bystanders.
check v0.1.1 v0.1.0 v0.1.0-rc.29 -- patch
check v0.2.0 v0.1.0 v0.1.0-rc.29 -- minor
check v1.0.0 v0.1.0 -- major

# Invalid arguments are refused.
check "(exit 2)" v0.1.0 -- rc nonsense
check "(exit 2)" v0.1.0 -- nonsense

if [ "$FAIL" -ne 0 ]; then
  echo "next-version-test: FAILURES above" >&2
  exit 1
fi
echo "next-version-test: all scenarios passed"
