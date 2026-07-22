#!/usr/bin/env bash
#
# get-sh-message-test.sh — regression test for get.sh's messaging and
# install-method selection (issues #235, #240).
#
# WHY (issue #235): before v0.1.0 ships, GitHub's /releases/latest 404s for
# every release (it only ever considers non-prerelease tags), and get.sh
# must turn that into an actionable message instead of a bare "could not
# determine latest version" — while NEVER silently installing a prerelease
# on the bare one-liner.
#
# WHY (issue #240): get.sh is package-first — it prefers apt/dnf over raw
# binaries when a package manager is present and the package repo is
# reachable, to stop a later `apt install` from silently being shadowed by
# script-installed binaries/units. This file also covers that routing
# (packages vs. binary fallback vs. explicit override) and `--uninstall`.
#
# This is exercised against a local mock of the GitHub API + package repo,
# and get.sh runs behind a dead proxy (see run_against_mock / run_get_sh) so
# any curl that is not aimed at the 127.0.0.1 mock fails instantly — zero
# real network calls, deterministic, safe to run on every PR, and
# structurally unable to download or install real binaries or packages even
# after v0.1.0 ships. The mock's stable tag is deliberately one that can
# never exist (v0.0.0-ci-mock) as a second layer of the same guarantee.
# Package-manager calls (apt-get/gpg/systemctl) are never real either — see
# setup_fakebin, which puts fake, logged, no-op scripts of those names
# first in PATH.
#
# Usage: bash scripts/get-sh-message-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GET_SH="$REPO_ROOT/scripts/get.sh"

pass=0; fail=0
ok()  { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[31m✗ %s\033[0m\n' "$1"; fail=$((fail+1)); }

# shellcheck disable=SC2016  # single quotes are the point: literal Python
# source, including a literal $(...) in the evil-tag fixture — nothing here
# may expand in the shell.
MOCK_SERVER_PY='
import http.server, json, sys

mode = sys.argv[1]

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/ezyshield.asc":
            # Package-repo signing-key endpoint: reachability probe AND the
            # source install_via_packages() pipes into the (faked, in tests)
            # gpg. Content is irrelevant here -- the fake gpg in
            # setup_fakebin() just copies stdin to -o, it never really
            # dearmors anything.
            self._json(200, {"not": "a real key, fine for the fake gpg"})
            return
        if self.path.startswith("/repos/evertramos/ezy-shield/releases/latest"):
            if mode == "200":
                # A tag that can never exist as a real release: even if this
                # test somehow escaped the dead-proxy net, the download URL
                # built from it 404s on github.com forever.
                self._json(200, {"tag_name": "v0.0.0-ci-mock", "assets": []})
            else:
                self._json(404, {"message": "Not Found"})
            return
        if self.path.startswith("/repos/evertramos/ezy-shield/releases?per_page=1"):
            if mode == "both-404":
                self._json(404, {"message": "Not Found"})
            elif mode == "evil-tag":
                self._json(200, [{"tag_name": "v0.1.0-rc.1$(touch /tmp/pwned)", "assets": []}])
            else:
                self._json(200, [{"tag_name": "v0.1.0-rc.999", "assets": []}])
            return
        self.send_response(404)
        self.end_headers()

srv = http.server.HTTPServer(("127.0.0.1", 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
'

# run_against_mock <mode> — launches a local mock of the GitHub releases API
# (modes: 404 | 200 | both-404 | evil-tag, see MOCK_SERVER_PY), runs the real
# get.sh against it via EZYSHIELD_API_BASE_URL, tears the mock down, and
# leaves the result in the globals OUT (combined stdout+stderr) and RC (exit
# code). get.sh runs behind a proxy pointed at a dead local port (no_proxy
# exempts the mock), so any request to a real host — github.com asset
# downloads included — fails instantly instead of touching the network.
#
# EZYSHIELD_METHOD=binary is forced here so these scenarios stay scoped to
# the release-resolution messaging (issue #235) regardless of whether the
# runner happens to have apt/dnf — the package-routing behavior (issue #240)
# is exercised separately below via run_get_sh_only. EZYSHIELD_ROOT points
# at an empty temp dir so the package-owned-host refusal guard (also #240)
# can never fire from the runner's real filesystem state.
run_against_mock() {
  local mode="$1"
  local portfile pid port emptyroot
  portfile="$(mktemp)"
  emptyroot="$(mktemp -d)"

  python3 -c "$MOCK_SERVER_PY" "$mode" >"$portfile" 2>/dev/null &
  pid=$!

  port=""
  for _ in $(seq 1 50); do
    port="$(cat "$portfile" 2>/dev/null || true)"
    [ -n "$port" ] && break
    sleep 0.1
  done
  rm -f "$portfile"

  if [ -z "$port" ]; then
    kill "$pid" 2>/dev/null || true
    rm -rf "$emptyroot"
    bad "mock server ($mode) never reported its port"
    OUT=""
    RC=99
    return
  fi

  set +e
  OUT="$(env \
    http_proxy="http://127.0.0.1:1" https_proxy="http://127.0.0.1:1" \
    HTTP_PROXY="http://127.0.0.1:1" HTTPS_PROXY="http://127.0.0.1:1" \
    no_proxy="127.0.0.1" NO_PROXY="127.0.0.1" \
    EZYSHIELD_METHOD=binary \
    EZYSHIELD_ROOT="$emptyroot" \
    EZYSHIELD_API_BASE_URL="http://127.0.0.1:${port}" sh "$GET_SH" 2>&1)"
  RC=$?
  set -e

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -rf "$emptyroot"
}

# setup_fakebin creates a temp directory with fake, logged, no-op apt-get,
# gpg, systemctl, and dpkg scripts, and points FAKEBIN at it. Every
# invocation is appended to CALLLOG (one line per call) so scenarios can
# assert exactly what did or did not run — in particular, that no real
# package-manager or systemd mutation ever happens in this test. The fake
# gpg mimics `gpg --dearmor -o <file>` by copying stdin to <file> verbatim
# (the mock's /ezyshield.asc body is not a real key, so real gpg would
# reject it). The fake dpkg answers exit 0 to every query — i.e. "yes, a
# package owns that file" — which the refusal-guard scenarios rely on; it
# is only ever consulted when ${EZYSHIELD_ROOT}/usr/bin/ezyshield exists.
setup_fakebin() {
  FAKEBIN="$(mktemp -d)"
  CALLLOG="$FAKEBIN/.calls"
  : >"$CALLLOG"

  cat >"$FAKEBIN/apt-get" <<'EOF'
#!/bin/sh
echo "apt-get $*" >>"$EZY_TEST_CALLLOG"
exit 0
EOF
  cat >"$FAKEBIN/gpg" <<'EOF'
#!/bin/sh
echo "gpg $*" >>"$EZY_TEST_CALLLOG"
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
cat >"$out"
EOF
  cat >"$FAKEBIN/systemctl" <<'EOF'
#!/bin/sh
echo "systemctl $*" >>"$EZY_TEST_CALLLOG"
exit 0
EOF
  cat >"$FAKEBIN/dpkg" <<'EOF'
#!/bin/sh
echo "dpkg $*" >>"$EZY_TEST_CALLLOG"
exit 0
EOF
  chmod +x "$FAKEBIN/apt-get" "$FAKEBIN/gpg" "$FAKEBIN/systemctl" "$FAKEBIN/dpkg"
}

# start_mock <mode> — launches the mock server (same one run_against_mock
# uses, now also serving /ezyshield.asc, see MOCK_SERVER_PY) and sets
# MOCK_PID/MOCK_PORT. Pair with stop_mock.
start_mock() {
  local mode="$1"
  local portfile
  portfile="$(mktemp)"

  python3 -c "$MOCK_SERVER_PY" "$mode" >"$portfile" 2>/dev/null &
  MOCK_PID=$!

  MOCK_PORT=""
  for _ in $(seq 1 50); do
    MOCK_PORT="$(cat "$portfile" 2>/dev/null || true)"
    [ -n "$MOCK_PORT" ] && break
    sleep 0.1
  done
  rm -f "$portfile"

  if [ -z "$MOCK_PORT" ]; then
    kill "$MOCK_PID" 2>/dev/null || true
    bad "mock server ($mode) never reported its port"
    return 1
  fi
}

stop_mock() {
  kill "$MOCK_PID" 2>/dev/null || true
  wait "$MOCK_PID" 2>/dev/null || true
}

# run_get_sh_only [extra get.sh args...] — runs the real get.sh behind the
# same dead-proxy net-block as run_against_mock, honoring an EXTRA_ENV array
# the caller populates beforehand (e.g. EZYSHIELD_METHOD=packages,
# EZYSHIELD_PACKAGES_BASE_URL=http://127.0.0.1:$MOCK_PORT,
# EZYSHIELD_ROOT=...) and, when FAKEBIN is set (see setup_fakebin),
# prepending it to PATH. Sets OUT/RC. Does NOT start/stop the mock server —
# call start_mock/stop_mock around it (needed because EXTRA_ENV often
# references MOCK_PORT, which only exists once the mock is already up).
run_get_sh_only() {
  local run_path="$PATH"
  if [ -n "${FAKEBIN:-}" ]; then
    run_path="$FAKEBIN:$PATH"
  fi

  set +e
  OUT="$(env \
    PATH="$run_path" \
    http_proxy="http://127.0.0.1:1" https_proxy="http://127.0.0.1:1" \
    HTTP_PROXY="http://127.0.0.1:1" HTTPS_PROXY="http://127.0.0.1:1" \
    no_proxy="127.0.0.1" NO_PROXY="127.0.0.1" \
    "${EXTRA_ENV[@]}" \
    sh "$GET_SH" "$@" 2>&1)"
  RC=$?
  set -e
}

command -v python3 >/dev/null 2>&1 || { echo "python3 required for the mock server"; exit 2; }

echo "▸ Scenario: no stable release yet (404) — must guide, never silently install"
run_against_mock 404
if [ "$RC" -eq 1 ]; then ok "exits 1 (no install attempted)"; else bad "exit code = $RC, want 1"; fi
case "$OUT" in
  *"Installing EzyShield"*) bad "output claims an install happened — must never proceed past the guidance" ;;
  *) ok "no 'Installing EzyShield' line (nothing was installed)" ;;
esac
for phrase in "No stable release has been published yet" "testing" "EZYSHIELD_VERSION=v0.1.0-rc.999"; do
  case "$OUT" in
    *"$phrase"*) ok "message contains '$phrase'" ;;
    *) bad "message MISSING '$phrase'" ;;
  esac
done

echo
echo "▸ Scenario: regression guard — a stable release still resolves normally (download blocked by dead proxy)"
run_against_mock 200
case "$OUT" in
  *"Installing EzyShield v0.0.0-ci-mock "*) ok "resolved the stable tag and proceeded toward install" ;;
  *) bad "did not resolve/proceed on a 200 response; output:
$OUT" ;;
esac
if [ "$RC" -ne 0 ]; then
  ok "exit != 0 (asset download blocked — nothing was actually installed)"
else
  bad "exit code = 0 — this test must never complete a real install"
fi
case "$OUT" in
  *"checksums.txt not found"*) ok "failed at the download step, not before (install genuinely attempted)" ;;
  *) bad "expected the checksums-download failure; output:
$OUT" ;;
esac

echo
echo "▸ Scenario: hostile tag_name from the API — never echoed into the copy-paste command"
run_against_mock evil-tag
if [ "$RC" -eq 1 ]; then ok "exits 1"; else bad "exit code = $RC, want 1"; fi
# shellcheck disable=SC2016  # matching a literal $( in the output — must not expand
case "$OUT" in
  *'$(touch'*) bad "hostile tag reached the printed copy-paste command" ;;
  *) ok "hostile tag was rejected before printing" ;;
esac
case "$OUT" in
  *"pick a tag from the list"*) ok "degrades to the generic releases-page pointer" ;;
  *) bad "missing the generic fallback pointer" ;;
esac

echo
echo "▸ Scenario: releases-list lookup also fails — degrade without crashing"
run_against_mock both-404
if [ "$RC" -eq 1 ]; then ok "exits 1"; else bad "exit code = $RC, want 1"; fi
case "$OUT" in
  *"No stable release has been published yet"*) ok "still explains the RC-only state" ;;
  *) bad "lost the actionable message when the RC-list lookup also failed" ;;
esac
case "$OUT" in
  *"pick a tag from the list"*) ok "falls back to the generic releases-page pointer" ;;
  *) bad "missing the generic fallback pointer" ;;
esac

echo
echo "▸ Scenario: package manager present + repo reachable — routes to repo setup, never curls binaries"
setup_fakebin
SANDBOX="$(mktemp -d)"
start_mock 404
EXTRA_ENV=(
  EZY_TEST_CALLLOG="$CALLLOG"
  EZYSHIELD_METHOD=packages
  EZYSHIELD_PACKAGES_BASE_URL="http://127.0.0.1:${MOCK_PORT}"
  EZYSHIELD_ROOT="$SANDBOX"
)
run_get_sh_only
stop_mock
if [ "$RC" -eq 0 ]; then ok "exits 0 (package install path completed)"; else bad "exit code = $RC, want 0; output:
$OUT"; fi
case "$OUT" in
  *"Package manager detected (apt)"*) ok "routed to repo setup" ;;
  *) bad "did not route to repo setup; output:
$OUT" ;;
esac
case "$OUT" in
  *"installed via apt"*) ok "reports the package install as complete" ;;
  *) bad "missing the package-install success message" ;;
esac
case "$OUT" in
  *"Installing EzyShield "*) bad "fell through to the binary-mode install message — must never curl binaries when packages succeed" ;;
  *) ok "never printed the binary-mode 'Installing EzyShield' message" ;;
esac
case "$OUT" in
  *"Fetching latest release"*) bad "fell through to the binary-mode release lookup — must never curl the releases API when packages succeed" ;;
  *) ok "never fetched the releases API (binary-mode-only step)" ;;
esac
CALLS="$(cat "$CALLLOG")"
case "$CALLS" in
  *"apt-get update"*) ok "ran apt-get update" ;;
  *) bad "apt-get update was never called; calls:
$CALLS" ;;
esac
case "$CALLS" in
  *"apt-get install -y ezyshield"*) ok "ran apt-get install -y ezyshield" ;;
  *) bad "apt-get install was never called; calls:
$CALLS" ;;
esac
rm -rf "$FAKEBIN" "$SANDBOX"

echo
echo "▸ Scenario: repo unreachable — falls back to binary install with a loud warning, packages never touched"
setup_fakebin
SANDBOX="$(mktemp -d)" # empty root: no package-owned install, guard must stay silent
start_mock 404
EXTRA_ENV=(
  EZY_TEST_CALLLOG="$CALLLOG"
  EZYSHIELD_METHOD=packages
  EZYSHIELD_API_BASE_URL="http://127.0.0.1:${MOCK_PORT}"
  EZYSHIELD_ROOT="$SANDBOX"
  # EZYSHIELD_PACKAGES_BASE_URL intentionally left unset: it defaults to the
  # real packages.ezyshield.com, which the dead proxy blocks instantly —
  # this IS the "repo unreachable" condition, no separate mock needed.
)
run_get_sh_only
stop_mock
if [ "$RC" -eq 1 ]; then ok "exits 1 (same as the plain binary-mode 404 case)"; else bad "exit code = $RC, want 1"; fi
case "$OUT" in
  *"could not reach the EzyShield package repository"*) ok "prints the loud unreachable-repo warning" ;;
  *) bad "missing the repo-unreachable warning; output:
$OUT" ;;
esac
case "$OUT" in
  *"No stable release has been published yet"*) ok "still falls all the way through to the normal binary-mode message" ;;
  *) bad "binary-mode fallback did not complete; output:
$OUT" ;;
esac
CALLS="$(cat "$CALLLOG")"
if [ -z "$CALLS" ]; then ok "apt-get/gpg were never invoked (repo setup correctly skipped)"; else bad "unexpected package-manager calls:
$CALLS"; fi
rm -rf "$FAKEBIN" "$SANDBOX"

echo
echo "▸ Scenario: EZYSHIELD_METHOD=binary skips packages entirely, even with apt-get present and repo reachable"
setup_fakebin
SANDBOX="$(mktemp -d)" # empty root: no package-owned install, guard must stay silent
start_mock 404
EXTRA_ENV=(
  EZY_TEST_CALLLOG="$CALLLOG"
  EZYSHIELD_METHOD=binary
  EZYSHIELD_API_BASE_URL="http://127.0.0.1:${MOCK_PORT}"
  EZYSHIELD_PACKAGES_BASE_URL="http://127.0.0.1:${MOCK_PORT}"
  EZYSHIELD_ROOT="$SANDBOX"
)
run_get_sh_only
stop_mock
case "$OUT" in
  *"Note: native .deb/.rpm packages are available"*) ok "surfaces the packages-available tip" ;;
  *) bad "missing the packages-available tip; output:
$OUT" ;;
esac
case "$OUT" in
  *"could not reach the EzyShield package repository"*) bad "probed repo reachability even though EZYSHIELD_METHOD=binary was set" ;;
  *) ok "never probed repo reachability (explicit binary override short-circuits it)" ;;
esac
case "$OUT" in
  *"No stable release has been published yet"*) ok "proceeded straight to the normal binary-mode message" ;;
  *) bad "binary-mode path did not complete; output:
$OUT" ;;
esac
CALLS="$(cat "$CALLLOG")"
if [ -z "$CALLS" ]; then ok "apt-get/gpg were never invoked"; else bad "unexpected package-manager calls:
$CALLS"; fi
rm -rf "$FAKEBIN" "$SANDBOX"

echo
echo "▸ Scenario: previous script install is cleaned up on transition to packages (EZYSHIELD_CLEANUP=1)"
setup_fakebin
SANDBOX="$(mktemp -d)"
mkdir -p "$SANDBOX/usr/local/bin" "$SANDBOX/etc/systemd/system" "$SANDBOX/usr/bin"
printf '#!/bin/sh\necho old\n' >"$SANDBOX/usr/local/bin/ezyshield"
printf '#!/bin/sh\necho old\n' >"$SANDBOX/usr/local/bin/ezyshield-enforcer"
cat >"$SANDBOX/etc/systemd/system/ezyshield.service" <<EOF
[Service]
ExecStart=$SANDBOX/usr/local/bin/ezyshield run
EOF
cat >"$SANDBOX/etc/systemd/system/ezyshield-enforcer.service" <<EOF
[Service]
ExecStart=$SANDBOX/usr/local/bin/ezyshield-enforcer
EOF
# Decoy package-managed binary — must survive untouched (proves cleanup
# never globs outside the exact script-install paths it knows about).
printf '#!/bin/sh\necho package\n' >"$SANDBOX/usr/bin/ezyshield"

start_mock 404
EXTRA_ENV=(
  EZY_TEST_CALLLOG="$CALLLOG"
  EZYSHIELD_METHOD=packages
  EZYSHIELD_PACKAGES_BASE_URL="http://127.0.0.1:${MOCK_PORT}"
  EZYSHIELD_ROOT="$SANDBOX"
  EZYSHIELD_CLEANUP=1
)
run_get_sh_only
stop_mock
case "$OUT" in
  *"Found a previous script install that would shadow the package install"*) ok "detected the shadowing script install" ;;
  *) bad "did not detect the shadowing install; output:
$OUT" ;;
esac
case "$OUT" in
  *"Cleanup complete."*) ok "ran the cleanup (EZYSHIELD_CLEANUP=1)" ;;
  *) bad "cleanup did not run; output:
$OUT" ;;
esac
if [ ! -e "$SANDBOX/usr/local/bin/ezyshield" ] && [ ! -e "$SANDBOX/usr/local/bin/ezyshield-enforcer" ]; then
  ok "shadowing binaries removed"
else
  bad "shadowing binaries still present under $SANDBOX/usr/local/bin"
fi
if [ ! -e "$SANDBOX/etc/systemd/system/ezyshield.service" ] && [ ! -e "$SANDBOX/etc/systemd/system/ezyshield-enforcer.service" ]; then
  ok "shadowing unit overrides removed"
else
  bad "shadowing unit overrides still present under $SANDBOX/etc/systemd/system"
fi
if [ -f "$SANDBOX/usr/bin/ezyshield" ]; then
  ok "package-managed decoy binary (/usr/bin/ezyshield) left untouched"
else
  bad "cleanup removed a file it does not own: $SANDBOX/usr/bin/ezyshield"
fi
CALLS="$(cat "$CALLLOG")"
case "$CALLS" in
  *"systemctl stop ezyshield ezyshield-enforcer"*) ok "stopped the shadowing services before removing files" ;;
  *) bad "did not stop services before cleanup; calls:
$CALLS" ;;
esac
rm -rf "$FAKEBIN" "$SANDBOX"

echo
echo "▸ Scenario: --uninstall removes script-install artifacts in a sandbox dir, package-managed files untouched"
setup_fakebin
SANDBOX="$(mktemp -d)"
mkdir -p "$SANDBOX/usr/local/bin" "$SANDBOX/etc/systemd/system" "$SANDBOX/usr/bin" "$SANDBOX/usr/lib/systemd/system"
printf '#!/bin/sh\necho old\n' >"$SANDBOX/usr/local/bin/ezyshield"
printf '#!/bin/sh\necho old\n' >"$SANDBOX/usr/local/bin/ezyshield-enforcer"
printf '[Service]\nExecStart=%s/usr/local/bin/ezyshield run\n' "$SANDBOX" >"$SANDBOX/etc/systemd/system/ezyshield.service"
printf '[Service]\nExecStart=%s/usr/local/bin/ezyshield-enforcer\n' "$SANDBOX" >"$SANDBOX/etc/systemd/system/ezyshield-enforcer.service"
# Package-managed files that --uninstall must never touch.
printf '#!/bin/sh\necho package\n' >"$SANDBOX/usr/bin/ezyshield"
printf '[Service]\nExecStart=/usr/bin/ezyshield run\n' >"$SANDBOX/usr/lib/systemd/system/ezyshield.service"

EXTRA_ENV=(EZY_TEST_CALLLOG="$CALLLOG" EZYSHIELD_ROOT="$SANDBOX")
run_get_sh_only --uninstall
if [ "$RC" -eq 0 ]; then ok "exits 0"; else bad "exit code = $RC, want 0; output:
$OUT"; fi
if [ ! -e "$SANDBOX/usr/local/bin/ezyshield" ] && [ ! -e "$SANDBOX/usr/local/bin/ezyshield-enforcer" ]; then
  ok "script-install binaries removed"
else
  bad "script-install binaries still present under $SANDBOX/usr/local/bin"
fi
if [ ! -e "$SANDBOX/etc/systemd/system/ezyshield.service" ] && [ ! -e "$SANDBOX/etc/systemd/system/ezyshield-enforcer.service" ]; then
  ok "script-install unit files removed"
else
  bad "script-install unit files still present under $SANDBOX/etc/systemd/system"
fi
if [ -f "$SANDBOX/usr/bin/ezyshield" ] && [ -f "$SANDBOX/usr/lib/systemd/system/ezyshield.service" ]; then
  ok "package-managed files (/usr/bin, /usr/lib/systemd/system) left untouched"
else
  bad "uninstall removed a package-managed file it does not own"
fi
rm -rf "$FAKEBIN" "$SANDBOX"

echo
echo "▸ Scenario: package-owned host + EZYSHIELD_METHOD=binary — refuses by default, points at apt/dnf"
setup_fakebin
SANDBOX="$(mktemp -d)"
mkdir -p "$SANDBOX/usr/bin"
printf '#!/bin/sh\necho package\n' >"$SANDBOX/usr/bin/ezyshield" # fake dpkg (exit 0) confirms ownership
start_mock 404
EXTRA_ENV=(
  EZY_TEST_CALLLOG="$CALLLOG"
  EZYSHIELD_METHOD=binary
  EZYSHIELD_API_BASE_URL="http://127.0.0.1:${MOCK_PORT}"
  EZYSHIELD_ROOT="$SANDBOX"
)
run_get_sh_only
stop_mock
if [ "$RC" -eq 1 ]; then ok "exits 1 (refused)"; else bad "exit code = $RC, want 1; output:
$OUT"; fi
case "$OUT" in
  *"already has a package-managed EzyShield install"*) ok "prints the refusal message" ;;
  *) bad "missing the refusal message; output:
$OUT" ;;
esac
case "$OUT" in
  *"apt install --only-upgrade ezyshield"*) ok "names the apt upgrade command" ;;
  *) bad "refusal does not name the apt upgrade command" ;;
esac
case "$OUT" in
  *"dnf upgrade ezyshield"*) ok "names the dnf upgrade command" ;;
  *) bad "refusal does not name the dnf upgrade command" ;;
esac
case "$OUT" in
  *"EZYSHIELD_FORCE_SCRIPT=1"*) ok "mentions the EZYSHIELD_FORCE_SCRIPT=1 override" ;;
  *) bad "refusal does not mention the override" ;;
esac
case "$OUT" in
  *"No stable release has been published yet"* | *"Fetching latest release"*) bad "reached the release lookup — refusal must come before any download step" ;;
  *) ok "refused before any release lookup or download" ;;
esac
if [ ! -e "$SANDBOX/usr/local/bin/ezyshield" ] && [ ! -e "$SANDBOX/usr/local/bin/ezyshield-enforcer" ]; then
  ok "nothing written to \${ROOT}/usr/local/bin"
else
  bad "refusal still wrote binaries under $SANDBOX/usr/local/bin"
fi
CALLS="$(cat "$CALLLOG")"
case "$CALLS" in
  *"dpkg -S /usr/bin/ezyshield"*) ok "consulted dpkg to confirm package ownership" ;;
  *) bad "dpkg ownership query never ran; calls:
$CALLS" ;;
esac
rm -rf "$FAKEBIN" "$SANDBOX"

echo
echo "▸ Scenario: package-owned host + EZYSHIELD_FORCE_SCRIPT=1 — proceeds past the refusal with a loud warning"
setup_fakebin
SANDBOX="$(mktemp -d)"
mkdir -p "$SANDBOX/usr/bin"
printf '#!/bin/sh\necho package\n' >"$SANDBOX/usr/bin/ezyshield"
start_mock 404
EXTRA_ENV=(
  EZY_TEST_CALLLOG="$CALLLOG"
  EZYSHIELD_METHOD=binary
  EZYSHIELD_FORCE_SCRIPT=1
  EZYSHIELD_API_BASE_URL="http://127.0.0.1:${MOCK_PORT}"
  EZYSHIELD_ROOT="$SANDBOX"
)
run_get_sh_only
stop_mock
case "$OUT" in
  *"already has a package-managed EzyShield install"*) bad "refusal message printed despite EZYSHIELD_FORCE_SCRIPT=1" ;;
  *) ok "refusal message absent (override honored)" ;;
esac
case "$OUT" in
  *"WILL shadow the package's /usr/bin ones"*) ok "prints the loud force-script shadowing warning" ;;
  *) bad "missing the force-script warning; output:
$OUT" ;;
esac
case "$OUT" in
  *"No stable release has been published yet"*) ok "proceeded to the normal binary-mode path (dies on the 404 guidance as usual)" ;;
  *) bad "did not reach the binary-mode release lookup; output:
$OUT" ;;
esac
if [ "$RC" -eq 1 ]; then ok "exits 1 (no stable release — nothing installed by this test)"; else bad "exit code = $RC, want 1"; fi
rm -rf "$FAKEBIN" "$SANDBOX"

echo
echo "▸ Scenario: repo-unreachable fallback on a package-owned host — the guard still refuses (fallback cannot bypass it)"
setup_fakebin
SANDBOX="$(mktemp -d)"
mkdir -p "$SANDBOX/usr/bin"
printf '#!/bin/sh\necho package\n' >"$SANDBOX/usr/bin/ezyshield"
start_mock 404
EXTRA_ENV=(
  EZY_TEST_CALLLOG="$CALLLOG"
  EZYSHIELD_METHOD=packages
  EZYSHIELD_API_BASE_URL="http://127.0.0.1:${MOCK_PORT}"
  EZYSHIELD_ROOT="$SANDBOX"
  # EZYSHIELD_PACKAGES_BASE_URL left unset: the dead proxy makes the real
  # repo host unreachable, forcing the binary fallback — which must then
  # hit the refusal guard instead of installing.
)
run_get_sh_only
stop_mock
if [ "$RC" -eq 1 ]; then ok "exits 1 (refused)"; else bad "exit code = $RC, want 1; output:
$OUT"; fi
case "$OUT" in
  *"could not reach the EzyShield package repository"*) ok "took the repo-unreachable fallback path first" ;;
  *) bad "missing the repo-unreachable warning; output:
$OUT" ;;
esac
case "$OUT" in
  *"already has a package-managed EzyShield install"*) ok "fallback hit the refusal guard" ;;
  *) bad "fallback bypassed the refusal guard; output:
$OUT" ;;
esac
case "$OUT" in
  *"No stable release has been published yet"* | *"Fetching latest release"*) bad "fallback reached the release lookup on a package-owned host" ;;
  *) ok "no release lookup or download was attempted" ;;
esac
if [ ! -e "$SANDBOX/usr/local/bin/ezyshield" ]; then
  ok "nothing written to \${ROOT}/usr/local/bin"
else
  bad "fallback still wrote binaries under $SANDBOX/usr/local/bin"
fi
rm -rf "$FAKEBIN" "$SANDBOX"

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
