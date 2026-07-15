#!/usr/bin/env bash
#
# mk-package-units.sh — generate the systemd units shipped inside deb/rpm
# packages. They are byte-identical to configs/systemd/ (the single source
# of truth for every hardening directive) except ExecStart: packages install
# binaries to /usr/bin (FHS), while script installs (scripts/get.sh) use
# /usr/local/bin. Called by goreleaser's before hook.

set -euo pipefail

cd "$(dirname "$0")/../.."
mkdir -p .gen/pkg-systemd

for unit in ezyshield.service ezyshield-enforcer.service; do
	sed 's|/usr/local/bin/|/usr/bin/|g' "configs/systemd/${unit}" > ".gen/pkg-systemd/${unit}"
done

echo "package units written to .gen/pkg-systemd/"
