# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Overview

vault is a post-quantum encrypted file vault: one `package main` at the repo
root that builds a single `vault` binary. Module `github.com/andydixon/vault`.

- `main.go` - CLI: `genkey`, `init`, `add`, `list`, `get`, `mv`, `rm`.
- `keyfile.go` - passphrase-protected key file (Argon2id +
  XChaCha20-Poly1305 sealing a suite ID and 32-byte master seed).
- `store.go` - on-disk vault: `records/` holds fixed-size encrypted catalogue
  records, `objects/` holds padded encrypted file bodies. Records a key cannot
  open are skipped, not treated as errors.
- `internal/pqcrypt` - file encryption (header + STREAM ChaCha20-Poly1305),
  suite registry, hybrid FrodoKEM-640 + ML-KEM-768 default suite.
- `internal/format`, `internal/stream`, `internal/term` - header encoding,
  chunked payload encryption, terminal passphrase prompts.

## Commands

```sh
go test ./...
go build .
```

End-to-end check:

```sh
export VAULT_PASSPHRASE=test VAULT_KEY=$PWD/k VAULT_DIR=$PWD/s
./vault genkey && ./vault init && ./vault add README.md docs && ./vault list
```

## Invariants

- Never write a seed or private key unencrypted.
- Keep suite IDs, stanza tags, HKDF info strings and `fileKeySize` (32) stable.
- Every ciphertext's mtime is pinned to the epoch; records stay one fixed
  size; objects stay bucket-padded. These hide metadata from the storage host.
- An object's plaintext starts with its own ID, binding it to its record.
- `get` publishes output only after the entire object has authenticated.
- Keep dependencies pure Go.
- Diagnostics go to standard error, lower-case, no trailing full stops.
