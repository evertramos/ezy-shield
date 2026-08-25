#!/bin/bash
# EzyShield launch demo (issue #232): a scripted, reproducible scenario —
# synthetic attack against a throwaway dry-run instance, showing detection,
# the strike ladder escalating on repeat offense, and the ban receipt.
#
# Honesty contract: everything shown is shipped behavior running for real
# (a live daemon, the real rule engine, the real store). It runs in DRY-RUN
# and says so on screen. The ONLY demo-specific tweak is the first strike's
# TTL (15s instead of 5m) so the re-offense escalation is visible in a
# 30-second recording — the policy file printed on screen shows exactly
# that. IPs are RFC 5737 documentation addresses; no root needed; nothing
# outside a temp directory is touched.
#
# Usage:  bash scripts/demo/demo.sh          # run it (also what the VHS tape drives)
# Record: vhs scripts/demo/demo.tape         # writes assets/demo/ezyshield-demo.gif
set -euo pipefail

say() { printf '\n\033[1;36m# %s\033[0m\n' "$*"; sleep "${DEMO_PAUSE:-1}"; }
run() { printf '\033[1;33m$ %s\033[0m\n' "$*"; "$@"; sleep "${DEMO_PAUSE:-1}"; }

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/bin/ezyshield"
if [ ! -x "$BIN" ]; then
  echo "building ezyshield..." >&2
  (cd "$ROOT" && CGO_ENABLED=0 go build -o bin/ezyshield ./cmd/ezyshield) >&2
fi

WORK="$(mktemp -d /tmp/ezyshield-demo.XXXXXX)"
cleanup() {
  if [ -n "${DAEMON_PID:-}" ]; then kill "$DAEMON_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
LOG="$WORK/access.log"
SOCK="$WORK/ezyshield.sock"
: > "$LOG"

cat > "$WORK/config.yaml" <<EOF
data_dir: $WORK
socket_path: $SOCK
log:
  level: warn
collectors:
  - kind: file
    path: $LOG
    parser: nginx
EOF

cat > "$WORK/policy.yaml" <<'EOF'
# DEMO policy — dry-run (nothing is enforced), first strike shortened to
# 15s so the ladder's escalation fits a 30-second recording.
armed: false
ban_threshold: 70
observe_threshold: 40
strikes:
  - ttl: 15s
  - ttl: 1h
  - ttl: 24h
  - ttl: 168h
  - ttl: 0
max_bans_per_minute: 30
allowlist: []
admin_cidrs: []
EOF

ATTACKER=203.0.113.66
hit() { # path status
  echo "$ATTACKER - - [01/Jan/2026:12:00:00 +0000] \"GET $1 HTTP/1.1\" $2 162 \"-\" \"python-requests/2.31\"" >> "$LOG"
}

say "EzyShield demo — a fresh dry-run instance in a temp dir (no root, nothing enforced)"
"$BIN" run --config "$WORK/config.yaml" --policy "$WORK/policy.yaml" \
  --db "$WORK/ezyshield.db" --socket "$SOCK" >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.2; done

run "$BIN" status --socket "$SOCK" || true

say "An attacker (203.0.113.66) probes wp-login.php — watch the rule fire"
for _ in 1 2 3 4; do hit /wp-login.php 200; done
sleep 3

run "$BIN" list --socket "$SOCK"

say "Strike 1: a (simulated) 15s ban. The attacker waits it out and keeps coming back..."
# Re-offend until the expired ban is purged (the daemon's expiry tick runs
# every minute) and the ladder escalates — exactly what a real bot does.
for _ in $(seq 1 12); do
  for _ in 1 2 3 4; do hit /wp-login.php 200; done
  sleep 7
  if "$BIN" list --socket "$SOCK" 2>/dev/null | grep -q "  2  "; then break; fi
done

say "Repeat offense = strike 2 — the ladder escalates to 1 hour"
run "$BIN" list --socket "$SOCK"

say "The receipt: WHY was this IP banned? Every strike, rule, and score:"
run "$BIN" report "$ATTACKER" --socket "$SOCK"

say "That's dry-run. Arm it ('ezyshield arm') and strike 2 would be a real 1h nftables + edge ban."
