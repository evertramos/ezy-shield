#!/usr/bin/env bash
#
# mk-completions-man.sh — generate the shell completions and man pages
# shipped inside the deb/rpm packages and release tarballs (issue #225).
#
# Builds the real `ezyshield` binary and asks it to walk its OWN cobra
# command tree via the hidden `__gendocs` subcommand, so the shipped docs
# can never drift from the actual CLI surface — there is no separate
# generator with a stub command tree to keep in sync. Called by
# goreleaser's before hook, alongside mk-package-units.sh.
#
# Output layout (relative to repo root):
#   .gen/completions/bash/ezyshield        -> /usr/share/bash-completion/completions/ezyshield
#   .gen/completions/zsh/_ezyshield        -> /usr/share/zsh/vendor-completions/_ezyshield
#   .gen/completions/fish/ezyshield.fish   -> /usr/share/fish/vendor_completions.d/ezyshield.fish
#   .gen/man/man1/ezyshield.1.gz (+ per-subcommand pages) -> /usr/share/man/man1/

set -euo pipefail

cd "$(dirname "$0")/../.."

OUT_COMPLETIONS=.gen/completions
OUT_MAN=.gen/man

rm -rf "$OUT_COMPLETIONS" "$OUT_MAN"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
tmp_bin="$tmp_dir/ezyshield"

# No ldflags here on purpose: this runs in goreleaser's before-hooks stage,
# before the version string is known, and the man page header intentionally
# doesn't embed it (see gendocs.go) — only the real command tree matters.
go build -o "$tmp_bin" ./cmd/ezyshield

"$tmp_bin" __gendocs "$OUT_COMPLETIONS" "$OUT_MAN"

# gzip the generated man pages in place; -n drops the filename/mtime from
# the gzip header so the output is reproducible across builds.
gzip -fn "$OUT_MAN"/man1/*.1

echo "completions written to $OUT_COMPLETIONS/, man pages written to $OUT_MAN/man1/"
