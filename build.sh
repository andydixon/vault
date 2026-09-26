#!/usr/bin/env bash
# Build vault for every OS and CPU architecture Go can target without cgo.
#
#   ./build.sh                          # everything, into ./dist
#   TARGETS="linux/amd64 darwin/arm64" ./build.sh
#   OUT=/tmp/release ./build.sh
#
# Binaries are static, stripped and reproducible (CGO_ENABLED=0, -trimpath).
# iOS and most Android targets are skipped (they need cgo); see below.
# 32-bit ARM Linux is built twice: armv6 (Raspberry Pi Zero/1) and armv7.
# SHA256SUMS is written next to the binaries.
set -euo pipefail
cd "$(dirname "$0")"

out=${OUT:-dist}
# iOS and 32-bit/x86 Android need cgo and a vendor SDK. android/arm64 builds
# a static binary that runs in Termux.
targets=${TARGETS:-$(go tool dist list | grep -vE '^ios/|^android/(386|amd64|arm)$')}
jobs=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}

rm -rf "$out"
mkdir -p "$out"

build_one() {
	local os=${1%/*} arch=${1#*/} variants=("") name ext=""
	[[ $os == windows ]] && ext=.exe
	[[ $arch == wasm ]] && ext=.wasm
	[[ $os/$arch == linux/arm ]] && variants=(6 7)
	for v in "${variants[@]}"; do
		name=vault-$os-$arch${v:+v$v}$ext
		if ! GOOS=$os GOARCH=$arch GOARM=${v:-} CGO_ENABLED=0 \
			go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$OUT_DIR/$name" . 2>"$OUT_DIR/$name.log"; then
			echo "FAILED $name" >&2
			cat "$OUT_DIR/$name.log" >&2
			return 1
		fi
		rm "$OUT_DIR/$name.log"
		echo "built  $name"
	done
}
export -f build_one
export OUT_DIR=$out

printf '%s\n' $targets | xargs -P "$jobs" -I{} bash -c 'build_one {}'

cd "$out"
if command -v sha256sum >/dev/null; then sha256sum vault-* >SHA256SUMS; else shasum -a 256 vault-* >SHA256SUMS; fi
echo "$(ls vault-* | wc -l | tr -d ' ') binaries in $out"
