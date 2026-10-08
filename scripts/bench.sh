#!/usr/bin/env bash
# Compare the Go oracle and the Rust build on this machine, end to end.
#
#   scripts/bench.sh [WORKDIR]        (default: target/bench, on the repo's disk)
#   RUNS=5 BIG_MB=2048 SMALL=5000 scripts/bench.sh
#
# For each implementation, in a fresh key and vault on the same filesystem:
# add one BIG_MB file, and add SMALL small files (1-16 KiB) as a folder, each
# into a fresh vault; then, in one vault holding both, get the big file,
# list the catalogue (filler plus SMALL+1 records), and get one small file. Each step is timed RUNS times (median, min, max), with peak RSS and
# peak thread count. Every step includes unlocking the key (two Argon2id
# runs). Both implementations fsync every object and record, so `add`
# timings include durable writes. Page caches are warm: dropping them needs
# root, so cold-cache numbers are not measured here.
#
# Needs: go (to build the oracle), cargo, /usr/bin/time (GNU).
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
work=${1:-$root/target/bench}
runs=${RUNS:-3}
big_mb=${BIG_MB:-1024}
small=${SMALL:-500}

mkdir -p -- "$work"
work=$(cd -- "$work" && pwd -P)
[[ $work == "$root" || $work == / ]] && { echo "refusing WORKDIR=$work" >&2; exit 2; }

cargo build --release --locked --quiet
(cd oracle/go && CGO_ENABLED=0 go build -trimpath -o "$work/vault-go" .)
cp target/release/vault "$work/vault-rust"

data=$work/data
if [[ ! -f $data/big || $(stat -c %s "$data/big") != $((big_mb << 20)) ]]; then
	rm -rf -- "$data"
	mkdir -p -- "$data/small"
	head -c $((big_mb << 20)) /dev/urandom >"$data/big"
	for i in $(seq -w 1 "$small"); do
		head -c $((1024 + RANDOM % 15360)) /dev/urandom >"$data/small/f$i"
	done
fi

export VAULT_PASSPHRASE=bench-passphrase

# measure LABEL CMD...: one timed run, printing "seconds rss_kib threads".
measure() {
	local out=$work/time.$$ peak=0 pid t
	/usr/bin/time -f '%e %M' -o "$out" "$@" >/dev/null 2>&1 &
	pid=$!
	while kill -0 $pid 2>/dev/null; do
		for t in /proc/[0-9]*/status; do
			if grep -q "^PPid:[[:space:]]*$pid$" "$t" 2>/dev/null; then
				n=$(awk '/^Threads:/{print $2}' "$t" 2>/dev/null || echo 0)
				((n > peak)) && peak=$n
			fi
		done
		sleep 0.05
	done
	wait $pid
	echo "$(cat "$out") $peak"
	rm -f -- "$out"
}

summarise() { # lines of "secs rss threads" -> median min max, max rss, max threads
	sort -n | awk '{t[NR]=$1; if($2>r)r=$2; if($3>th)th=$3} END {printf "%8.2f s (min %.2f, max %.2f)  rss %6.0f MiB  threads %d\n", t[int((NR+1)/2)], t[1], t[NR], r/1024, th}'
}

fresh() { # fresh key and vault at $1
	rm -rf -- "$1"
	mkdir -p -- "$1"
	export VAULT_KEY=$1/key VAULT_DIR=$1/store
	"$bin" genkey 2>/dev/null
	"$bin" init 2>/dev/null
}

for impl in go rust; do
	bin=$work/vault-$impl
	echo "== $impl ($(stat -c %s "$bin") bytes)"
	# Writes: a fresh vault for every run.
	for step in add-big add-small; do
		results=""
		for run in $(seq 1 "$runs"); do
			fresh "$work/run-$impl"
			case $step in
			add-big) r=$(measure "$bin" add "$data/big") ;;
			add-small) r=$(measure "$bin" add "$data/small") ;;
			esac
			results+="$r"$'\n'
		done
		printf '  %-10s ' "$step"
		printf '%s' "$results" | grep . | summarise
	done
	# Reads: one populated vault, read repeatedly.
	v=$work/run-$impl
	fresh "$v"
	"$bin" add "$data/big" 2>/dev/null
	"$bin" add "$data/small" 2>/dev/null
	for step in get-big list get-small; do
		results=""
		for run in $(seq 1 "$runs"); do
			rm -f -- "$v/big.out" "$v/small.out"
			case $step in
			get-big) r=$(measure "$bin" get big -o "$v/big.out") ;;
			list) r=$(measure "$bin" list) ;;
			get-small) r=$(measure "$bin" get "small/f$(printf "%0${#small}d" 1)" -o "$v/small.out") ;;
			esac
			results+="$r"$'\n'
		done
		printf '  %-10s ' "$step"
		printf '%s' "$results" | grep . | summarise
	done
	rm -rf -- "$work/run-$impl"
done
