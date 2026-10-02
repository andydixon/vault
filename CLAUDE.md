# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Overview

vault is a post-quantum encrypted file vault: one `package main` at the repo
root that builds a single `vault` binary. Module `github.com/andydixon/vault`.

- `main.go` - CLI: `genkey`, `init`, `add` (file, directory
  or URL), `migrate` (add, then delete originals), `mirror`, `absorb` (tar
  on stdin, `absorb.go`), `list`, `get`, `mv`, `rm`.
- `keyfile.go` - key file with two passphrase slots (Argon2id +
  XChaCha20-Poly1305 sealing a suite ID and 32-byte master seed). The second
  slot is either a decoy identity or random bytes; slot order is random.
- `store.go` - on-disk vault: `records/` holds fixed-size encrypted catalogue
  records, `objects/` holds file bodies cut into 4 MiB chunks (last one
  bucket-padded) whose IDs are HMAC'd from a per-record seed. Both are
  sharded into 256 `xx/` subdirectories by ID prefix. Records a key cannot
  open are skipped, not treated as errors.
- `lock*.go` - vault lock on `DIR/.lock`: fcntl on unix, LockFileEx on
  Windows, an exclusive lock file elsewhere. Writers lock exclusively,
  readers shared, taken after the passphrase prompt.
- `docs/guide` - LaTeX user guide (`build-pdf.sh` via Tectonic; `shots.py`
  re-shoots screenshots from the real binary). Keep it in step with the CLI.
- `build.sh` - cross-compiles every `go tool dist list` target except
  iOS and android/386, amd64, arm (cgo-only).
- `internal/pqcrypt` - file encryption (header + STREAM ChaCha20-Poly1305),
  suite registry, hybrid FrodoKEM-640 + ML-KEM-768 default suite.
- `internal/format`, `internal/stream`, `internal/term` - header encoding,
  chunked payload encryption, terminal passphrase prompts.

## Commands

```sh
go test ./...
go build .
./build.sh                                  # all platforms, into ./dist
TARGETS="linux/amd64" ./build.sh            # a subset
```

End-to-end check:

```sh
export VAULT_PASSPHRASE=test VAULT_KEY=$PWD/k VAULT_DIR=$PWD/s
./vault genkey && ./vault init && ./vault add README.md docs && ./vault list
```

## Invariants

- Never write a seed or private key unencrypted.
- Keep suite IDs, stanza tags, HKDF info strings and `fileKeySize` (32) stable.
- Every ciphertext's and shard directory's mtime is pinned to the epoch;
  records stay one fixed size; objects stay at most 4 MiB and bucket-padded.
  These hide metadata from the storage host.
- An object's plaintext starts with its own ID, binding it to its record
  and its position in the file.
- `get` publishes output only after every object has authenticated.
- Decoy deniability: both key slots stay the same size and are both always
  tried; `init` always writes filler; foreign records are skipped silently.
- Every command that changes the vault holds the exclusive lock.
- Keep dependencies pure Go and CGO_ENABLED=0 builds working.
- Diagnostics go to standard error, lower-case, no trailing full stops.
