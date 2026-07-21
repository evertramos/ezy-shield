#!/usr/bin/env bash
#
# get-sh-message-test.sh — regression test for the get.sh "no stable release
# yet" message path (issue #235).
#
# WHY: before v0.1.0 ships, GitHub's /releases/latest 404s for every release
# (it only ever considers non-prerelease tags), and get.sh must turn that
# into an actionable message instead of a bare "could not determine latest
# version" — while NEVER silently installing a prerelease on the bare
# one-liner. This is exercised against a local mock of the GitHub API, and
# get.sh runs behind a dead proxy (see run_against_mock) so any curl that
# is not aimed at the 127.0.0.1 mock fails instantly — zero real network
# calls, deterministic, safe to run on every PR, and structurally unable
# to download or install real binaries even after v0.1.0 ships. The mock's
# stable tag is deliberately one that can never exist (v0.0.0-ci-mock) as
# a second layer of the same guarantee.
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
run_against_mock() {
  local mode="$1"
  local portfile pid port
  portfile="$(mktemp)"

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
    EZYSHIELD_API_BASE_URL="http://127.0.0.1:${port}" sh "$GET_SH" 2>&1)"
  RC=$?
  set -e

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
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
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
