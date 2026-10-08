#!/usr/bin/env bash
# Build the dixon-vault .deb, .rpm and Arch packages locally and show what
# is in them. Nothing is signed or published: packaging/repo.sh does that,
# reusing this script's build step.
#
#   packaging/package.sh                  # from the working tree, into dist/packages
#   packaging/package.sh v0.6             # from a tag (a clean export of it)
#   OUT=/tmp/pkgs ARCHS="amd64 arm64" packaging/package.sh
#
# Needs: the pinned Rust toolchain with cargo-zigbuild and zig (the static
# Linux binaries are cross-built), and go, only to run the pinned nfpm
# packager. dpkg-deb, rpm and zstd are used for inspection when present.
# None of these is needed to run vault itself.
#
#   ARCHS            package architectures (default below)
#   RPM_SIGNING_KEY  armoured private key file to sign the .rpm with
#                    (repo.sh sets it; unset here means unsigned)
set -euo pipefail

# ---- project ---------------------------------------------------------------
NAME=vault           # the command
# The package: plain "vault" is HashiCorp Vault in Arch's [extra] and in
# HashiCorp's own apt and dnf repositories, which would win upgrades. Both
# install /usr/bin/vault, so they conflict.
PACKAGE=dixon-vault
CONFLICTS=vault
SUMMARY="Post-quantum encrypted file vault with a decoy passphrase"
HOMEPAGE=https://dixon.cx/vault
LICENSE=GPL-3.0-or-later
MANPAGES=docs/*.1
DOCS="README.md LICENSE SECURITY.md"
# Package architecture -> Rust target (all static musl binaries).
triple() {
	case $1 in
	amd64) echo x86_64-unknown-linux-musl ;;
	arm64) echo aarch64-unknown-linux-musl ;;
	arm) echo armv7-unknown-linux-musleabihf ;;
	386) echo i686-unknown-linux-musl ;;
	riscv64) echo riscv64gc-unknown-linux-musl ;;
	*) return 1 ;;
	esac
}
# ----------------------------------------------------------------------------

ARCHS=${ARCHS:-"amd64 arm64 arm 386 riscv64"}
NFPM="go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.1"

say() { echo "package: $*" >&2; }
die() { say "$*"; exit 1; }

# build_packages SRC OUTDIR VERSION: binaries, then one .deb, .rpm and
# .pkg.tar.zst per architecture, into OUTDIR.
build_packages() {
	local src=$1 outdir=$2 version=$3 arch nfarch t work
	for tool in cargo cargo-zigbuild zig go; do
		command -v $tool >/dev/null || die "needs $tool"
	done
	work=$(mktemp -d)
	mkdir -p "$outdir"
	for arch in $ARCHS; do
		t=$(triple "$arch") || die "no Rust target for $arch"
		nfarch=$arch
		[[ $arch == arm ]] && nfarch=arm7
		say "building $NAME for $arch ($t)"
		flags="--remap-path-prefix=$src=vault"
		# zig's musl getrandom() never reaches the kernel on riscv64; have
		# the getrandom crate issue the system call itself.
		[[ $t == riscv64*-musl ]] && flags+=' --cfg getrandom_backend="linux_raw"'
		(cd "$src" && RUSTFLAGS=$flags cargo zigbuild --quiet --release --locked --target "$t") || die "build for $arch failed"
		install -D -m 0755 "$src/target/$t/release/$NAME" "$work/bin-$arch/$NAME"
		{
			cat <<-EOF
			name: $PACKAGE
			arch: $nfarch
			platform: linux
			version: $version
			release: 1
			maintainer: Andy Dixon <andy@dixon.cx>
			description: $SUMMARY
			homepage: $HOMEPAGE
			license: $LICENSE
			conflicts: [${CONFLICTS:-}]
			contents:
			  - src: $work/bin-$arch/$NAME
			    dst: /usr/bin/$NAME
			    file_info: {mode: 0755}
			EOF
			for m in $(cd "$src" && ls $MANPAGES); do
				printf '  - src: %s\n    dst: /usr/share/man/man1/%s\n    file_info: {mode: 0644}\n' \
					"$src/$m" "$(basename "$m")"
			done
			for d in $DOCS; do
				printf '  - src: %s\n    dst: /usr/share/doc/%s/%s\n    file_info: {mode: 0644}\n' \
					"$src/$d" "$PACKAGE" "$d"
			done
			if [[ -n ${RPM_SIGNING_KEY:-} ]]; then
				printf 'rpm:\n  signature:\n    key_file: %s\n' "$RPM_SIGNING_KEY"
			fi
		} >"$work/nfpm-$arch.yaml"
		for fmt in deb rpm archlinux; do
			$NFPM pkg -f "$work/nfpm-$arch.yaml" -p $fmt -t "$outdir/" >/dev/null
		done
	done
	rm -rf -- "$work"
}

# inspect_packages DIR: list each package's metadata and files.
inspect_packages() {
	local p
	for p in "$1"/*; do
		echo "== $(basename "$p")"
		case $p in
		*.deb) if command -v dpkg-deb >/dev/null; then dpkg-deb -f "$p" Package Version Architecture Conflicts; dpkg-deb -c "$p"; fi ;;
		*.rpm) if command -v rpm >/dev/null; then rpm -qpi "$p" 2>/dev/null | head -12; rpm -qplv "$p"; fi ;;
		*.pkg.tar.zst) if command -v zstd >/dev/null; then zstd -dcq "$p" | tar -tvf -; fi ;;
		esac
	done
}

# When run (not sourced by repo.sh): build from the tree or a tag, inspect.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	cd "$(git rev-parse --show-toplevel)"
	out=${OUT:-dist/packages}
	mkdir -p -- "$out"
	out=$(cd -- "$out" && pwd -P)
	rm -f -- "$out"/*.deb "$out"/*.rpm "$out"/*.pkg.tar.zst
	if [[ $# -gt 0 ]]; then
		git rev-parse -q --verify "refs/tags/$1" >/dev/null || die "no tag $1"
		src=$(mktemp -d)
		trap 'rm -rf -- "$src"' EXIT
		git archive "$1" | tar -x -C "$src"
		version=${1#v}
	else
		src=$PWD
		version=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import sys,json; print(json.load(sys.stdin)["packages"][0]["version"])')
	fi
	build_packages "$src" "$out" "$version"
	inspect_packages "$out"
	say "$(ls "$out" | wc -l) packages in $out (unsigned, not published)"
fi
