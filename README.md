# vault

A post-quantum encrypted file vault in a single binary.

Files are encrypted with a hybrid FrodoKEM-640 + ML-KEM-768 key encapsulation
and ChaCha20-Poly1305. The vault directory holds only randomly named
ciphertexts. Names, sizes, modes and timestamps live inside encrypted
catalogue records of one fixed size. File bodies are cut into 4 MiB objects,
the last padded to a power-of-two bucket, so every object is 64 KiB to 4 MiB
whatever the file's size. Object names derive from a secret seed in the
record, so nothing on disk links a file's pieces. Records and objects are
spread over 256 subfolders (`records/3f/3fa9…`) to keep directories small.

## Install

On Debian, Ubuntu, Fedora, RHEL, openSUSE and Arch, install the
`dixon-vault` package from the signed repository at repo.dixon.cx; see
https://dixon.cx/repo for the two or three commands. (The package isn't
called `vault` because that name is HashiCorp Vault's.) Every platform also
has a single binary at https://download.dixon.cx/vault/.

Releases are packaged and published with `packaging/repo.sh [TAG]`.

## Build

vault is written in Rust (the toolchain is pinned in `rust-toolchain.toml`;
`rustup` installs it on first use). Releases up to 0.5 were Go; the Go code
lives on, frozen, in `oracle/go` as the test reference. Nothing at run time
needs Go.

```sh
cargo build --release --locked      # produces target/release/vault
cargo test --locked                 # unit, CLI and Go-interoperability tests
./build.sh                          # every target this host can build, into ./dist
TARGETS="linux/amd64 windows/amd64" ./build.sh
```

`build.sh` cross-compiles with `cargo-zigbuild` and `zig` (Linux, statically
linked with musl, and Windows), on a Mac for macOS, and with `cross` and
Docker for FreeBSD. The release covers Linux, Windows, macOS and FreeBSD. It names binaries as before
(`vault-linux-arm64`, `vault-windows-amd64.exe`, …), builds 32-bit ARM Linux
for both armv6 and armv7, and writes `dist/SHA256SUMS`. `docs/PLATFORMS.md`
lists every target, how it is built and tested, and the Go targets Rust
cannot build.

The interoperability tests build the Go oracle when `go` is installed and
are skipped (and say so) otherwise; set `VAULT_REQUIRE_ORACLE=1` to make a
missing oracle an error, as CI does. `oracle/gen-vectors.sh` regenerates the
Go test vectors. Packages are built and inspected locally, unsigned, with
`packaging/package.sh`, and published with `packaging/repo.sh [TAG]`.

Further reading: `SECURITY.md` (what is and is not protected, memory and
filesystem guarantees), `docs/COMPATIBILITY.md` (the formats),
`docs/MIGRATION.md` (what changed from the Go version) and
`docs/BENCHMARKS.md`.

## User guide

A full illustrated guide lives in `docs/guide`. Build the PDF with
`docs/guide/build-pdf.sh`, which fetches Tectonic if it isn't installed.
`docs/guide/shots.py` regenerates its screenshots from the real binary.

## Man pages

`docs/*.1` holds `vault(1)` and one page per command (`vault-add(1)`,
`vault-mirror(1)` and so on). Install them with
`cp docs/*.1 ~/.local/share/man/man1/`.

## Use

```sh
vault genkey                     # create ~/.vault/key, protected by a passphrase
vault init                       # create ~/.vault/store
vault init --filler 2G           # the same, with at least 2 GiB of filler
vault add report.pdf             # stored as report.pdf
vault add report.pdf work/2026   # stored as work/2026/report.pdf
vault add ./photos               # every regular file under photos/
vault add https://example.com/a.pdf   # download and store a URL
vault migrate ./photos           # like add, then delete the originals
vault mirror https://example.com/     # crawl a site into example.com/, links rewritten
tar -cz photos | vault absorb backup  # every file in a tar (or .tar.gz) under backup/
vault absorb backup < photos.tar.gz   # same, from an existing archive
vault ls                         # the top level: folders (ending in /) and files
vault ls work                    # one level down, inside work/
vault list                       # every file, all the way down, full names
vault list work                  # everything under work/
vault get work/2026/report.pdf   # writes ./report.pdf
vault get report.pdf -o copy.pdf
vault get -r work                # a whole folder, into ./work
vault mv report.pdf old/report.pdf
vault mv report.pdf old/         # the same: into a folder, like mv(1)
vault mv work archive/work       # folders move too
vault cp -r work work-backup     # instant; copies share their encrypted data
vault rm old/report.pdf
vault rm -r old                  # a whole folder; lists it and asks first
vault rm -rf old                 # the same, without asking
vault unlock                     # remember the key for 5 minutes (--for 30m)
vault unlock --idle              # ... or until 5 minutes go by unused
vault lock                       # forget it now
```

Commands that change the vault take an exclusive lock on `DIR/.lock`, and
commands that read it take a shared one. A second process waits, and says
so, until the first finishes. The operating system releases the lock if a
process dies; the locks are the same ones the Go version used, so old and
new versions exclude each other.

Adding a name that already exists replaces it. `get` never replaces an
existing file (or symlink) and writes nothing until the whole file has
authenticated. `add URL` and `mirror` have size and time limits; see
`vault(1)`.

`--key PATH` and `--vault DIR` work with every command. They default to
`$VAULT_KEY` and `$VAULT_DIR`, then to `~/.vault/key` and `~/.vault/store`.
The passphrase is read from the terminal, or from `$VAULT_PASSPHRASE` for
scripts.

`vault unlock` asks once, then starts a helper process, like `ssh-agent`,
that holds the unlocked key in memory until a hard deadline (5 minutes by
default; with `--idle`, 5 minutes since a command last used it) or
`vault lock`. Until then commands skip the prompt, unless
`$VAULT_PASSPHRASE` is set, which always wins. The key reaches the helper
over a pipe and never touches the disk; the helper's memory is locked
against swapping, it cannot be core-dumped (or, on Linux, debugged), and it
answers only on a socket in a directory private to your user. While it is
unlocked, anything running as you can use the vault, decoy or not, so lock
before handing the machine over. If the helper cannot protect its memory it
refuses the key. `unlock` is not available on Windows.

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

Default filler is only a few tens of megabytes, so someone holding the decoy
passphrase can see when far more data than that is unopenable. To hide more,
create the vault with `vault init --filler SIZE` (`500M`, `2G`, `1T`), at
least as large as what you will hide. Filler entries are written by the
same code as real files, with a spread of small and multi-chunk sizes, so
they look like a real collection. Filler can only be added at `init`;
added later it would stand out as a burst of new entries.

## Limits

- The storage host can see how many records and objects exist, so roughly
  how much is stored, and when the vault changes. Chunking hides a file's
  size in any single snapshot, but objects written together can be grouped
  by anyone watching the folder or a sync service's upload log.
- Padding still costs space: small files round up to a 64 KiB-or-larger
  bucket and a big file's last piece to its bucket, at most 4 MiB per file.
- The key file is the only way in. Losing it or its passphrase loses the data.

## Licence

GPL-3.0-or-later. The cryptographic core is derived from Fury.
