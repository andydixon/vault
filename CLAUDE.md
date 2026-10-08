# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Overview

vault is a post-quantum encrypted file vault: one Rust package (`Cargo.toml`
at the root, toolchain pinned in `rust-toolchain.toml`) that builds a single
`vault` binary. The library (`src/lib.rs`) exists so tests and benchmarks can
reach the same code; `src/main.rs` only calls `cli::main`.

- `src/cli.rs` - commands and Go-`flag`-compatible parsing: `genkey`,
  `init`, `add` (file, directory or URL), `migrate`, `mirror`, `absorb`,
  `ls`/`list`, `get` (`-r`), `mv`/`cp` (`transfers` resolves names like
  mv(1)), `rm` (`-r`, asks unless `-f`), `unlock`/`lock`, hidden `__agent`.
- `src/agent.rs` - the unlock agent: `unlock` re-executes the binary as
  `__agent` (passphrase variables stripped, secret over a pipe); it hardens
  itself (`platform::memory`) before reading the key, serves it on a Unix
  socket in a 0700 per-user dir until a deadline (fixed or `--idle`).
  Wire-compatible with the Go agent. Not available on Windows.
- `src/keyfile.rs` - key file: two Argon2id/XChaCha20-Poly1305 slots, decoy
  or random bytes in the second, random order, both always tried.
- `src/crypto/` - `frodo.rs` (FrodoKEM-640-SHAKE ported from CIRCL v1.6.4),
  `kem.rs` (hybrid suite 0x0001 with RustCrypto ml-kem, `Identity`),
  `header.rs` (Fury header format), `fury.rs` (file encryption), `stream.rs`
  (STREAM, including random access).
- `src/store/` - on-disk vault: `records/`, `objects/` sharded by ID prefix,
  catalogue, add/remove/copy/extract, filler; `types.rs` holds the validated
  types (`VaultName`, `Id`, `ObjectSeed`, `Record`) and record JSON.
- `src/pipeline.rs` - the one bounded worker pool and the eight reusable
  object buffers; coordinators run on the caller's thread.
- `src/platform/` - all `unsafe` and OS specifics: `fs.rs` (no-clobber
  publish, `Dir` confined extraction, epoch times, dir sync), `lock.rs`
  (fcntl / LockFileEx / lock file), `memory.rs` (mlock, undumpable),
  `term.rs` (prompts).
- `src/net/` - `add URL` and `mirror` with limits; `url.rs` (Go `net/url`
  semantics), `html.rs` (tokenizer and link rewriting).
- `src/absorb.rs` - tar (optionally gzipped) from stdin, streamed in.
- `src/secret.rs`, `src/rng.rs`, `src/util.rs`, `src/error.rs` - secret
  buffers, randomness (seeded only under `cfg(test)`), Go-compatible
  parsing/printing helpers, the error type.
- `oracle/go` - the frozen Go implementation (test-only reference, see
  `oracle/README.md`); `oracle/gen-vectors.sh` writes `tests/vectors`.
- `tests/` - CLI and interoperability tests against the real binaries;
  `fuzz/` - cargo-fuzz targets; `benches/micro.rs` - micro-benchmarks.
- `docs/` - man pages, `COMPATIBILITY.md`, `MIGRATION.md`, `PLATFORMS.md`,
  `BENCHMARKS.md`, and the LaTeX guide (`docs/guide`, `build-pdf.sh` via
  Tectonic; `shots.py` re-shoots screenshots from the real binary). Keep
  them in step with the CLI.
- `build.sh` - cross-builds every supported target (see `PLATFORMS.md`).
- `packaging/package.sh` builds and inspects dixon-vault packages locally;
  `packaging/repo.sh [TAG]` signs and publishes them to repo.dixon.cx.

## Commands

```sh
cargo test --locked                     # needs go on PATH for interop tests
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
cargo build --release --locked
./build.sh                              # all buildable targets, into ./dist
TARGETS="linux/amd64" ./build.sh        # a subset
cargo deny --locked check               # advisories and licences
(cd fuzz && cargo +nightly fuzz run header)
```

End-to-end check:

```sh
export VAULT_PASSPHRASE=test VAULT_KEY=$PWD/k VAULT_DIR=$PWD/s
target/release/vault genkey && target/release/vault init && target/release/vault add README.md docs && target/release/vault list
```

## Invariants

- The on-disk formats are frozen and shared with the Go version; check any
  change against `docs/COMPATIBILITY.md` and the oracle vectors.
- Never write a seed or private key unencrypted (the agent gets it by pipe).
- Keep suite IDs, stanza tags, HKDF info strings and the 32-byte file key stable.
- Every ciphertext's and shard directory's mtime is pinned to the epoch;
  records stay one fixed size; objects stay at most 4 MiB and bucket-padded.
  These hide metadata from the storage host.
- An object's plaintext starts with its own ID, binding it to its record
  and its position in the file.
- `get` publishes output only after every object has authenticated, with a
  no-replace primitive; never fall back to check-then-rename.
- Decoy deniability: both key slots stay the same size and are both always
  tried; `init` always writes filler; foreign records are skipped silently.
- Every command that changes the vault holds the exclusive lock (POSIX
  fcntl locks, compatible with Go's).
- Crash-safe order: objects before records, new records before removing old
  ones, record removal (synced) before object removal.
- Secrets live in `SecretArray`/`SecretVec`/`LockedBuf`: no Clone, Debug or
  serialisation. Production randomness is the OS only.
- `unsafe` only in `src/platform`, each block with a SAFETY comment.
- Diagnostics go to standard error, lower-case, no trailing full stops.
