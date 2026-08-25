#!/bin/sh
#
# Regression test for the package lifecycle scripts (issue #354).
#
# The bug: preremove stopped both units unconditionally — deb passes
# "upgrade" and rpm passes "1" on every upgrade — and postinstall never
# restarted anything, so `apt/dnf upgrade ezyshield` silently took the
# protection stack down permanently (fail-open upgrade).
#
# This test runs the real scripts with every systemd/user-management
# command stubbed out via PATH, then asserts:
#   - preremove on UPGRADE (deb "upgrade" / rpm "1") stops nothing
#   - preremove on REMOVAL (deb "remove" / rpm "0" / no arg) stops both units
#   - postinstall on UPGRADE (deb "configure <old>" / rpm "2") try-restarts both units
#   - postinstall on FRESH INSTALL (deb "configure" / rpm "1") starts/restarts nothing
#
# Run: sh scripts/package-lifecycle-test.sh   (CI: docs job)

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

STUB="$TMP/bin"
LOG="$TMP/calls.log"
mkdir -p "$STUB" "$TMP/systemd"

# ── stubs ────────────────────────────────────────────────────────────────────
# systemctl: log every invocation; report units as ACTIVE so the removal
# path exercises its stop branch.
cat > "$STUB/systemctl" <<EOF
#!/bin/sh
echo "systemctl \$*" >> "$LOG"
exit 0
EOF
# getent: pretend user and group already exist so postinstall skips creation.
cat > "$STUB/getent" <<'EOF'
#!/bin/sh
exit 0
EOF
# install: directory creation is not under test.
cat > "$STUB/install" <<'EOF'
#!/bin/sh
exit 0
EOF
# usermod: log group-membership changes (issue #454 — journal read access).
cat > "$STUB/usermod" <<EOF
#!/bin/sh
echo "usermod \$*" >> "$LOG"
exit 0
EOF
chmod +x "$STUB"/*

run() { # run <script> [args...]
	: > "$LOG"
	script="$1"
	shift
	PATH="$STUB:$PATH" EZYSHIELD_SYSTEMD_DIR="$TMP/systemd" \
		sh "$ROOT/scripts/package/$script" "$@" >/dev/null 2>&1
}

fails=0
assert_logged() { # assert_logged <label> <pattern>
	if ! grep -q "$2" "$LOG"; then
		echo "FAIL [$1]: expected a call matching '$2', log was:" >&2
		sed 's/^/    /' "$LOG" >&2 || true
		fails=$((fails + 1))
	fi
}
assert_not_logged() { # assert_not_logged <label> <pattern>
	if grep -q "$2" "$LOG"; then
		echo "FAIL [$1]: forbidden call matching '$2' found, log was:" >&2
		sed 's/^/    /' "$LOG" >&2
		fails=$((fails + 1))
	fi
}

# ── preremove: upgrade must not stop anything ────────────────────────────────
run preremove.sh upgrade
assert_not_logged "preremove deb upgrade" "systemctl stop"

run preremove.sh 1
assert_not_logged "preremove rpm upgrade" "systemctl stop"

# ── preremove: removal must stop both units ──────────────────────────────────
run preremove.sh remove
assert_logged "preremove deb remove" "systemctl stop ezyshield.service"
assert_logged "preremove deb remove" "systemctl stop ezyshield-enforcer.service"

run preremove.sh 0
assert_logged "preremove rpm erase" "systemctl stop ezyshield.service"

run preremove.sh
assert_logged "preremove no-arg (conservative removal)" "systemctl stop ezyshield.service"

# ── postinstall: upgrade must try-restart both units ─────────────────────────
run postinstall.sh configure 0.1.0
assert_logged "postinstall deb upgrade" "systemctl try-restart ezyshield-enforcer.service"
assert_logged "postinstall deb upgrade" "systemctl try-restart ezyshield.service"

run postinstall.sh 2
assert_logged "postinstall rpm upgrade" "systemctl try-restart ezyshield.service"

# ── postinstall: fresh install must not start or restart anything ────────────
run postinstall.sh configure
assert_not_logged "postinstall deb fresh" "systemctl try-restart"
assert_not_logged "postinstall deb fresh" "systemctl start"
assert_not_logged "postinstall deb fresh" "systemctl enable"

run postinstall.sh 1
assert_not_logged "postinstall rpm fresh" "systemctl try-restart"
assert_not_logged "postinstall rpm fresh" "systemctl start"

# ── postinstall: journal group membership (issue #454) ───────────────────────
# The journald collector runs as the service user; without systemd-journal
# membership it can never read the journal. Every postinstall run must add it
# (usermod -aG is idempotent), and on UPGRADE the usermod must come before
# the try-restart — supplementary groups are resolved at process start.
run postinstall.sh configure
assert_logged "postinstall deb fresh journal group" "usermod -aG systemd-journal ezyshield"

run postinstall.sh 1
assert_logged "postinstall rpm fresh journal group" "usermod -aG systemd-journal ezyshield"

run postinstall.sh configure 0.1.0
assert_logged "postinstall deb upgrade journal group" "usermod -aG systemd-journal ezyshield"
um_line=$(grep -n "usermod -aG systemd-journal" "$LOG" | head -n 1 | cut -d: -f1)
tr_line=$(grep -n "systemctl try-restart" "$LOG" | head -n 1 | cut -d: -f1)
if [ -z "$um_line" ] || [ -z "$tr_line" ] || [ "$um_line" -ge "$tr_line" ]; then
	echo "FAIL [postinstall upgrade ordering]: usermod (line ${um_line:-none}) must run before try-restart (line ${tr_line:-none}), log was:" >&2
	sed 's/^/    /' "$LOG" >&2 || true
	fails=$((fails + 1))
fi

if [ "$fails" -gt 0 ]; then
	echo "package-lifecycle-test: $fails assertion(s) failed" >&2
	exit 1
fi
echo "package-lifecycle-test: OK"
