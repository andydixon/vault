#!/usr/bin/env bash
# Runtime smoke test of one vault binary, optionally under an emulator:
# create a key and vault, store files across object boundaries, read them
# back, then (if a reference binary is given) check the reference can read
# what this binary wrote and the other way round.
#
#   scripts/smoke.sh BINARY [REFERENCE_BINARY]
#   EMU="qemu-aarch64" scripts/smoke.sh dist/vault-linux-arm64 target/release/vault
#
# Uses a private temporary directory, removed afterwards. The passphrase is
# a public test value.
set -euo pipefail
bin=$(realpath "$1")
ref=${2:+$(realpath "$2")}
emu=${EMU:-}
work=$(mktemp -d "${TMPDIR:-/tmp}/vault-smoke.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
cd "$work"
export VAULT_PASSPHRASE=smoke-test-passphrase VAULT_KEY=$work/key VAULT_DIR=$work/store
export XDG_RUNTIME_DIR=$work/run
mkdir -m 700 run
v() { $emu "$bin" "$@"; }

v genkey 2>/dev/null
v init 2>/dev/null
head -c $((4 * 1024 * 1024 + 123)) /dev/urandom >big
printf 'small\n' >small
: >empty
v add big 2>/dev/null
v add small dir 2>/dev/null
v add empty dir 2>/dev/null
[[ $(v list | wc -l) == 3 ]] || { echo "FAIL list"; exit 1; }
v get big -o big.out 2>/dev/null && cmp big big.out
v get dir/small -o small.out 2>/dev/null && cmp small small.out
if [[ -n $ref ]]; then
	"$ref" get big -o big.ref 2>/dev/null && cmp big big.ref
	printf 'from the reference\n' >r.txt
	"$ref" add r.txt 2>/dev/null
	v get r.txt -o r.out 2>/dev/null && cmp r.txt r.out
fi
v rm -rf dir 2>/dev/null
[[ $(v list | wc -l) == $([[ -n $ref ]] && echo 2 || echo 1) ]] || { echo "FAIL rm"; exit 1; }
echo "ok $(basename "$bin")${emu:+ (under $emu)}"
