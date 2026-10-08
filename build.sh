#!/usr/bin/env bash
# Build vault for the supported operating systems and CPU architectures.
#
#   ./build.sh                                   # every target this host can build, into ./dist
#   TARGETS="linux/amd64 darwin/arm64" ./build.sh
#   OUT=/tmp/release JOBS=4 ./build.sh
#
# Binaries keep the Go-era names, vault-OS-ARCH[.exe], and are stripped
# release builds from the pinned toolchain (rust-toolchain.toml) and the
# locked dependencies (Cargo.lock), with build paths remapped so the output
# does not depend on where the tree lives. Linux binaries are static (musl)
# except s390x, which links glibc dynamically; static linking is
# checked. SHA256SUMS is written next to the binaries.
#
# How each target is built, and what the host needs:
#   zig    cargo-zigbuild and zig on PATH  (Linux, Windows GNU ABI)
#   mac    a Mac with Xcode, or zig        (macOS; zig builds trust the
#                                            bundled Mozilla roots, not the
#                                            keychain)
#   cross  `cross` and Docker               (FreeBSD)
# A requested target the host cannot build is reported, the others are still
# built, and the script exits non-zero. See docs/PLATFORMS.md for the Go
# targets with no Rust equivalent; asking for one is an error.
#
# JOBS builds several targets at once, each in its own target directory
# under target/build-sh (default 1: one at a time, cargo using every CPU).
set -euo pipefail
cd "$(dirname "$0")"
root=$PWD

table() {
	# os/arch         Rust target                       method
	cat <<-'EOF'
	linux/amd64       x86_64-unknown-linux-musl         zig
	linux/arm64       aarch64-unknown-linux-musl        zig
	linux/386         i686-unknown-linux-musl           zig
	linux/armv6       arm-unknown-linux-musleabihf      zig
	linux/armv7       armv7-unknown-linux-musleabihf    zig
	linux/riscv64     riscv64gc-unknown-linux-musl      zig
	linux/loong64     loongarch64-unknown-linux-musl    zig
	linux/ppc64le     powerpc64le-unknown-linux-musl    zig
	linux/s390x       s390x-unknown-linux-gnu           zig
	windows/amd64     x86_64-pc-windows-gnu             zig
	windows/386       i686-pc-windows-gnu               zig
	windows/arm64     aarch64-pc-windows-gnullvm        zig
	darwin/amd64      x86_64-apple-darwin               mac
	darwin/arm64      aarch64-apple-darwin              mac
	freebsd/amd64     x86_64-unknown-freebsd            cross
	freebsd/386       i686-unknown-freebsd              cross
	EOF
}

# Go-era targets no longer released (the release covers Linux, Windows,
# macOS and FreeBSD). See docs/PLATFORMS.md for why each was dropped.
unsupported="aix/ppc64 android/arm64 dragonfly/amd64 freebsd/arm freebsd/arm64 freebsd/riscv64
illumos/amd64 js/wasm linux/mips linux/mipsle linux/mips64 linux/mips64le linux/ppc64
netbsd/386 netbsd/amd64 netbsd/arm netbsd/arm64 openbsd/386 openbsd/amd64 openbsd/arm
openbsd/arm64 openbsd/ppc64 openbsd/riscv64 plan9/386 plan9/amd64 plan9/arm solaris/amd64 wasip1/wasm"

out=${OUT:-dist}
jobs=${JOBS:-1}
targets=${TARGETS:-$(table | awk '{print $1}')}

# Never clean anything but our own output, and never in a directory that
# matters: OUT must be a dedicated directory, not /, $HOME or the tree.
mkdir -p -- "$out"
out=$(cd -- "$out" && pwd -P)
case $out in
/ | "$(cd ~ && pwd -P)" | "$root") echo "refusing OUT=$out: use a dedicated directory" >&2; exit 2 ;;
esac
rm -f -- "$out"/vault-* "$out"/SHA256SUMS

export CARGO_TARGET_DIR_BASE=$root/target/build-sh
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$root=vault --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=cargo"
export OUT_DIR=$out JOBS_N=$jobs HOST_OS=$(uname -s) root
logs=$root/target/build-sh-logs
mkdir -p -- "$logs"
export logs

build_one() {
	local want=$1 row os triple method name ext="" tdir bin
	row=$(table | awk -v t="$want" '$1 == t')
	if [[ -z $row ]]; then
		if grep -qw -- "$want" <<<"$unsupported"; then
			echo "UNSUPPORTED $want: not released; see docs/PLATFORMS.md" >&2
		else
			echo "UNKNOWN $want" >&2
		fi
		return 1
	fi
	read -r _ triple method <<<"$row"
	os=${want%/*}
	[[ $os == windows ]] && ext=.exe
	name=vault-${want/\//-}$ext
	tdir=$root/target
	[[ $JOBS_N != 1 ]] && tdir=$CARGO_TARGET_DIR_BASE/$triple
	case $method in
	zig)
		command -v cargo-zigbuild >/dev/null && command -v zig >/dev/null ||
			{ echo "SKIPPED $want: needs cargo-zigbuild and zig" >&2; return 1; }
		cmd=(cargo zigbuild) ;;
	mac)
		if [[ $HOST_OS == Darwin ]]; then
			cmd=(cargo build)
		elif command -v cargo-zigbuild >/dev/null && command -v zig >/dev/null; then
			# Without Apple's SDK there is no Security framework to link, so
			# the cross-built binary trusts the bundled Mozilla roots rather
			# than the macOS keychain.
			cmd=(cargo zigbuild --no-default-features)
		else
			echo "SKIPPED $want: needs a Mac, or cargo-zigbuild and zig" >&2; return 1
		fi ;;
	cross)
		command -v cross >/dev/null && command -v docker >/dev/null ||
			{ echo "SKIPPED $want: needs cross and docker" >&2; return 1; }
		cmd=(cross build) ;;
	esac
	local flags=$RUSTFLAGS
	# zig's musl getrandom() never reaches the kernel on riscv64 (it spins);
	# make the getrandom crate issue the system call itself.
	[[ $triple == riscv64*-musl ]] && flags+=' --cfg getrandom_backend="linux_raw"'
	if ! RUSTFLAGS=$flags CARGO_TARGET_DIR=$tdir "${cmd[@]}" --release --locked --target "$triple" >"$logs/$name.log" 2>&1; then
		echo "FAILED $want ($triple)" >&2
		tail -20 "$logs/$name.log" >&2
		return 1
	fi
	bin=$tdir/$triple/release/vault$ext
	cp -- "$bin" "$OUT_DIR/$name"
	if [[ $triple == *-musl* ]] && command -v file >/dev/null; then
		file -L "$OUT_DIR/$name" | grep -q 'static' || { echo "FAILED $want: not statically linked" >&2; return 1; }
	fi
	echo "built  $name ($triple)"
}
export -f build_one table
export unsupported

status=0
printf '%s\n' $targets | xargs -P "$jobs" -I{} bash -c 'build_one {}' || status=1

cd -- "$out"
if ls vault-* >/dev/null 2>&1; then
	if command -v sha256sum >/dev/null; then sha256sum vault-* >SHA256SUMS; else shasum -a 256 vault-* >SHA256SUMS; fi
fi
echo "$(ls vault-* 2>/dev/null | wc -l | tr -d ' ') binaries in $out"
exit $status
