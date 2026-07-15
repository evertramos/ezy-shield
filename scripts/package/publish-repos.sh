#!/usr/bin/env bash
#
# publish-repos.sh — build, sign, and publish the apt/yum repositories served
# at https://packages.ezyshield.com (issue #99, backed by Cloudflare R2).
#
# Suites: stable tags (vX.Y.Z) land in the "stable" suite; prerelease tags
# (-rc/-alpha/-beta) land in "testing". Each suite has its own apt pool and
# yum tree, so an rc can never leak into machines tracking stable.
#
# Layout inside the bucket / repo root:
#   apt/pool/<suite>/...                 .deb files
#   apt/dists/<suite>/{InRelease,Release,Release.gpg,main/binary-<arch>/Packages{,.gz}}
#   rpm/<suite>/{x86_64,aarch64}/{*.rpm,repodata/...,repodata/repomd.xml.asc}
#   ezyshield.asc                        armored public signing key
#
# Subcommands:
#   generate <packages-dir> <repo-root> <suite>
#       Add the .deb/.rpm files from <packages-dir> to <repo-root> and
#       (re)generate + sign all metadata for <suite>. Requires the signing
#       key in the active GPG keyring; set GPG_KEY_ID (fingerprint or id)
#       and, for non-interactive signing, GPG_PASSPHRASE.
#   sync <repo-root>
#       Ordered upload to R2: packages first, metadata last, never deletes.
#       Requires R2_ENDPOINT, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY,
#       R2_BUCKET.
#
# Local end-to-end test (throwaway key, no R2):
#   export GNUPGHOME=$(mktemp -d); gpg --batch --passphrase '' \
#     --quick-generate-key 'test <t@example.invalid>' rsa3072 sign never
#   GPG_KEY_ID=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/{print $5; exit}') \
#     ./scripts/package/publish-repos.sh generate dist/ /tmp/repo testing

set -euo pipefail

APT_ARCHES=(amd64 arm64)

gpg_sign_args() {
	# --pinentry-mode loopback lets CI sign without a tty. An empty
	# passphrase (throwaway test keys) works with the same flags.
	printf '%s\n' --batch --yes --pinentry-mode loopback \
		--passphrase "${GPG_PASSPHRASE:-}" --local-user "${GPG_KEY_ID:?set GPG_KEY_ID}"
}

generate() {
	local pkgdir=$1 root=$2 suite=$3
	local sign_args
	mapfile -t sign_args < <(gpg_sign_args)

	case "$suite" in
	stable | testing) ;;
	*)
		echo "ERROR: suite must be 'stable' or 'testing', got '$suite'" >&2
		return 1
		;;
	esac

	# ── ingest packages into the suite's pool/tree ─────────────────────────
	mkdir -p "$root/apt/pool/$suite" "$root/rpm/$suite/x86_64" "$root/rpm/$suite/aarch64"
	local found=0
	for deb in "$pkgdir"/*.deb; do
		[ -e "$deb" ] || continue
		cp -f "$deb" "$root/apt/pool/$suite/"
		found=1
	done
	for rpmf in "$pkgdir"/*.rpm; do
		[ -e "$rpmf" ] || continue
		case "$rpmf" in
		*amd64.rpm | *x86_64.rpm) cp -f "$rpmf" "$root/rpm/$suite/x86_64/" ;;
		*arm64.rpm | *aarch64.rpm) cp -f "$rpmf" "$root/rpm/$suite/aarch64/" ;;
		*)
			echo "ERROR: cannot map $rpmf to an rpm architecture" >&2
			return 1
			;;
		esac
		found=1
	done
	if [ "$found" -eq 0 ]; then
		echo "ERROR: no .deb/.rpm files found in $pkgdir" >&2
		return 1
	fi

	# ── apt metadata ───────────────────────────────────────────────────────
	local dist="$root/apt/dists/$suite"
	for arch in "${APT_ARCHES[@]}"; do
		mkdir -p "$dist/main/binary-$arch"
		# Paths in Packages must be relative to the apt root (pool/...).
		(cd "$root/apt" && dpkg-scanpackages --multiversion --arch "$arch" "pool/$suite" /dev/null) \
			>"$dist/main/binary-$arch/Packages"
		gzip -9 -c "$dist/main/binary-$arch/Packages" >"$dist/main/binary-$arch/Packages.gz"
	done

	apt-ftparchive \
		-o "APT::FTPArchive::Release::Origin=EzyShield" \
		-o "APT::FTPArchive::Release::Label=EzyShield" \
		-o "APT::FTPArchive::Release::Suite=$suite" \
		-o "APT::FTPArchive::Release::Codename=$suite" \
		-o "APT::FTPArchive::Release::Architectures=${APT_ARCHES[*]}" \
		-o "APT::FTPArchive::Release::Components=main" \
		release "$dist" >"$dist/Release"
	gpg "${sign_args[@]}" --clearsign -o "$dist/InRelease" "$dist/Release"
	gpg "${sign_args[@]}" --armor --detach-sign -o "$dist/Release.gpg" "$dist/Release"

	# ── yum metadata ───────────────────────────────────────────────────────
	for arch in x86_64 aarch64; do
		createrepo_c --update "$root/rpm/$suite/$arch" >/dev/null
		gpg "${sign_args[@]}" --armor --detach-sign \
			-o "$root/rpm/$suite/$arch/repodata/repomd.xml.asc" \
			"$root/rpm/$suite/$arch/repodata/repomd.xml"
	done

	# ── public key at the repo root ────────────────────────────────────────
	gpg --armor --export "$GPG_KEY_ID" >"$root/ezyshield.asc"

	echo "repo generated: suite=$suite root=$root"
}

rclone_r2() {
	RCLONE_CONFIG_R2_TYPE=s3 \
		RCLONE_CONFIG_R2_PROVIDER=Cloudflare \
		RCLONE_CONFIG_R2_ENDPOINT="${R2_ENDPOINT:?}" \
		RCLONE_CONFIG_R2_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID:?}" \
		RCLONE_CONFIG_R2_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY:?}" \
		rclone "$@"
}

sync_up() {
	local root=$1 bucket="${R2_BUCKET:?}"
	# Phase 1: immutable artifacts (packages) — clients following stale
	# metadata still resolve every file it references.
	rclone_r2 copy "$root" "r2:$bucket" \
		--filter '- /apt/dists/**' --filter '- repodata/**' --filter '+ **'
	# Phase 2: metadata + key, only after every package is in place. copy
	# (not sync) — publishing never deletes previously released versions.
	rclone_r2 copy "$root/apt/dists" "r2:$bucket/apt/dists"
	local dir
	for dir in "$root"/rpm/*/*/repodata; do
		[ -d "$dir" ] || continue
		rclone_r2 copy "$dir" "r2:$bucket/${dir#"$root"/}"
	done
	rclone_r2 copyto "$root/ezyshield.asc" "r2:$bucket/ezyshield.asc"
	echo "repo synced to r2:$bucket"
}

sync_down() {
	local root=$1 bucket="${R2_BUCKET:?}"
	mkdir -p "$root"
	# Pull current state so regenerated metadata covers previously published
	# versions too. An empty/new bucket is fine.
	rclone_r2 copy "r2:$bucket" "$root" || true
	echo "current repo state pulled from r2:$bucket"
}

case "${1:-}" in
generate) generate "${2:?packages dir}" "${3:?repo root}" "${4:?suite}" ;;
sync) sync_up "${2:?repo root}" ;;
sync-down) sync_down "${2:?repo root}" ;;
*)
	echo "usage: $0 generate <packages-dir> <repo-root> <stable|testing> | sync-down <repo-root> | sync <repo-root>" >&2
	exit 2
	;;
esac
