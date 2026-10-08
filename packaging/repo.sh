#!/usr/bin/env bash
# Build Linux packages (.deb, .rpm, Arch .pkg.tar.zst) for a release tag and
# publish them to the signed apt, dnf and pacman repositories served at
# https://repo.dixon.cx.
#
#   packaging/repo.sh          # the newest tag
#   packaging/repo.sh 0.5      # a given tag
#
# Builds from a clean export of the tag, so the working tree doesn't matter.
# Every index is rebuilt over all the packages in the repository, so other
# projects publishing there with their copy of this script are kept.
#
# Needs: the pinned Rust toolchain with cargo-zigbuild and zig, go (to run
# nfpm), docker, gpg, apt-ftparchive (apt-utils), flock.
#   REPO_DIR        where the repository lives (default below)
#   REPO_GNUPGHOME  GnuPG home holding the signing key (default below)
#   ARCHS           architectures to package (see packaging/package.sh)
#
# To build and inspect packages without signing or publishing, run
# packaging/package.sh instead.
#
# The same script, with its own project block, is in ../mapsize/packaging.
set -euo pipefail

# The project (package name, contents, architectures) and the build live in
# packaging/package.sh, which can also be run on its own to build and inspect
# packages without signing or publishing anything.
. "$(dirname "$0")/package.sh"

REPO_DIR=${REPO_DIR:-/home/andy/domains/repo.dixon.cx/public_html}
REPO_GNUPGHOME=${REPO_GNUPGHOME:-$HOME/.config/repo.dixon.cx/gnupg}
SUITE=stable
COMPONENT=main
ARCH_REPO=dixon # the pacman repository name: [dixon]

say() { echo "repo: $*" >&2; }
die() { say "$*"; exit 1; }

for tool in cargo cargo-zigbuild zig go docker gpg apt-ftparchive flock; do
	command -v $tool >/dev/null || die "needs $tool"
done
[[ -d $REPO_DIR ]] || die "$REPO_DIR does not exist"
export GNUPGHOME=$REPO_GNUPGHOME
KEY=$(gpg --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
[[ -n $KEY ]] || die "no signing key in $GNUPGHOME"

cd "$(git rev-parse --show-toplevel)"
TAG=${1:-$(git describe --tags --abbrev=0)}
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || die "no tag $TAG"
VERSION=${TAG#v}
export VERSION

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/src"
git archive "$TAG" | tar -x -C "$WORK/src"
gpg --batch --armor --export-secret-keys "$KEY" >"$WORK/signing.asc"

# ---- build ----------------------------------------------------------------
say "building $PACKAGE $VERSION for $ARCHS"
RPM_SIGNING_KEY=$WORK/signing.asc build_packages "$WORK/src" "$WORK/out" "$VERSION"

# ---- publish ---------------------------------------------------------------
# One publisher at a time: the indexes cover every project's packages.
exec 9>"$REPO_DIR/../.publish.lock"
flock 9
say "publishing to $REPO_DIR"
gpg --batch --armor --export "$KEY" >"$REPO_DIR/dixon.asc"
gpg --batch --export "$KEY" >"$REPO_DIR/dixon.gpg"
sign() { gpg --batch --yes --local-user "$KEY" "$@"; }

# apt: pool/main/<letter>/<name>/, indexed by apt-ftparchive.
pool=$REPO_DIR/apt/pool/$COMPONENT/${PACKAGE:0:1}/$PACKAGE
mkdir -p "$pool"
cp "$WORK"/out/*.deb "$pool/"
(
	cd "$REPO_DIR/apt"
	# Built beside the live suite and swapped in, so clients never see half.
	dists=dists/.$SUITE.new
	rm -rf "$dists"
	debarchs=$(find pool -name '*.deb' | sed -E 's/.*_([^_]+)\.deb$/\1/' | sort -u | tr '\n' ' ')
	for a in $debarchs; do
		d=$dists/$COMPONENT/binary-$a
		mkdir -p "$d"
		apt-ftparchive --arch "$a" packages pool >"$d/Packages"
		gzip -9kn "$d/Packages"
	done
	apt-ftparchive \
		-o APT::FTPArchive::Release::Origin=repo.dixon.cx \
		-o APT::FTPArchive::Release::Label=repo.dixon.cx \
		-o APT::FTPArchive::Release::Suite=$SUITE \
		-o APT::FTPArchive::Release::Codename=$SUITE \
		-o APT::FTPArchive::Release::Components=$COMPONENT \
		-o "APT::FTPArchive::Release::Architectures=${debarchs% }" \
		release "$dists" >"$WORK/Release"
	mv "$WORK/Release" "$dists/Release"
	sign --clearsign -o "$dists/InRelease" "$dists/Release"
	sign --armor --detach-sign -o "$dists/Release.gpg" "$dists/Release"
	rm -rf "dists/.$SUITE.old"
	[[ -d dists/$SUITE ]] && mv "dists/$SUITE" "dists/.$SUITE.old"
	mv "$dists" "dists/$SUITE"
	rm -rf "dists/.$SUITE.old"
)

# dnf: every architecture in one directory; dnf picks its own.
mkdir -p "$REPO_DIR/rpm"
cp "$WORK"/out/*.rpm "$REPO_DIR/rpm/"
docker image inspect repo-tools:fedora >/dev/null 2>&1 ||
	docker build -q -t repo-tools:fedora - >/dev/null <<-'EOF'
	FROM fedora:42
	RUN dnf -y install createrepo_c && dnf clean all
	EOF
docker run --rm --user "$(id -u):$(id -g)" -v "$REPO_DIR/rpm:/repo" repo-tools:fedora \
	createrepo_c --quiet --update --general-compress-type=gz /repo
sign --armor --detach-sign -o "$REPO_DIR/rpm/repodata/repomd.xml.asc" "$REPO_DIR/rpm/repodata/repomd.xml"
cat >"$REPO_DIR/rpm/dixon.repo" <<EOF
[dixon]
name=repo.dixon.cx
baseurl=https://repo.dixon.cx/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://repo.dixon.cx/dixon.asc
EOF

# pacman: one directory per architecture, each package signed, then
# repo-add (from an Arch container) and a signed database.
added=
for pkg in "$WORK"/out/*.pkg.tar.zst; do
	a=$(basename "$pkg" .pkg.tar.zst)
	a=${a##*-}
	mkdir -p "$REPO_DIR/arch/$a"
	cp "$pkg" "$REPO_DIR/arch/$a/"
	sign --detach-sign -o "$REPO_DIR/arch/$a/$(basename "$pkg").sig" "$pkg"
	added+=" $a"
done
for a in $(tr ' ' '\n' <<<"$added" | sort -u); do
	dir=$REPO_DIR/arch/$a
	# A fresh database of every package here; -p keeps the newest version.
	rm -f "$dir/$ARCH_REPO".{db,files}{,.tar.gz}{,.sig}
	docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$dir:/repo" -w /repo archlinux:latest \
		sh -c "repo-add --quiet --prevent-downgrade $ARCH_REPO.db.tar.gz *.pkg.tar.zst" 2>&1 |
		{ grep -v "newer version\|^$" >&2 || true; }
	for db in $ARCH_REPO.db $ARCH_REPO.files; do
		sign --detach-sign -o "$dir/$db.tar.gz.sig" "$dir/$db.tar.gz"
		ln -sfn "$db.tar.gz.sig" "$dir/$db.sig"
	done
	rm -f "$dir"/*.old "$dir"/*.old.sig
done

say "published $PACKAGE $VERSION: $(cd "$WORK/out" && ls | wc -l) packages"
