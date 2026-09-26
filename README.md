# vault

A post-quantum encrypted file vault in a single binary.

Files are encrypted with a hybrid FrodoKEM-640 + ML-KEM-768 key encapsulation
and ChaCha20-Poly1305. The vault directory holds only randomly named
ciphertexts. Names, sizes, modes and timestamps live inside encrypted
catalogue records of one fixed size. File bodies are padded to power-of-two
buckets.

## Build

```sh
go build .        # produces ./vault
go test ./...
```

## Use

```sh
vault genkey                     # create ~/.vault/key, protected by a passphrase
vault init                       # create ~/.vault/store
vault add report.pdf             # stored as report.pdf
vault add report.pdf work/2026   # stored as work/2026/report.pdf
vault add ./photos               # every regular file under photos/
vault list                       # everything
vault list work                  # everything under work/
vault get work/2026/report.pdf   # writes ./report.pdf
vault get report.pdf -o copy.pdf
vault mv report.pdf old/report.pdf
vault rm old/report.pdf
```

Adding a name that already exists replaces it. `get` refuses to overwrite an
existing file and writes nothing until the whole object has authenticated.

`--key PATH` and `--vault DIR` work with every command. They default to
`$VAULT_KEY` and `$VAULT_DIR`, then to `~/.vault/key` and `~/.vault/store`.
The passphrase is read from the terminal, or from `$VAULT_PASSPHRASE` for
scripts.

## Decoy passphrase

`vault genkey` offers an optional second passphrase. In scripts, set
`$VAULT_DECOY_PASSPHRASE`. Each passphrase unlocks its own key, so a command
run with the decoy passphrase lists, adds and retrieves only decoy files. The
real files never appear.

```sh
vault genkey                          # set a passphrase, then a decoy passphrase
vault add plans.pdf                   # with the real passphrase
vault add shopping.txt                # with the decoy passphrase
vault list                            # shows only what that passphrase stored
```

Two measures keep the real files deniable:

- The key file always holds two slots of identical size in random order. An
  unused slot is random bytes, so the file does not show whether a decoy
  exists or which slot is real.
- `init` fills every vault with 8 to 32 random entries that nobody can
  decrypt. Anyone holding only the decoy passphrase sees unreadable entries in
  every vault, so hidden real files look the same as filler.

A decoy can only be set when the key is created. Someone who watches the
vault over time can still see it grow when real files are added.

## Limits

- One writer at a time. Concurrent writes to the same vault are not locked.
- The storage host can see how many files exist, their size buckets and when
  the vault changes.
- The key file is the only way in. Losing it or its passphrase loses the data.

## Licence

GPL-3.0-or-later. The cryptographic core is derived from Fury.
