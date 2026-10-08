# Migrating from the Go implementation

vault 0.6 is a rewrite in Rust of the Go vault (0.5 and earlier). It is an
implementation migration only: key files, vaults, the lock and the unlock
agent are the same formats, byte for byte where the format is
deterministic (see `COMPATIBILITY.md`). There is nothing to convert. Go and
Rust builds can be used on the same vault, even at the same time: they
honour each other's locks, and either can use an agent the other started.

To go back, install 0.5: everything 0.6 writes, 0.5 reads.

## Intentional behaviour changes

Safety and correctness:

- **`get` never replaces anything.** Output is published with an atomic
  no-replace rename or link, so a file, a symlink (even a dangling one) or a
  file created while `get` runs is left alone. Go checked first and then
  renamed, which a concurrent creator could race.
- **`get -r` does not follow symlinks inside the output directory.** Each
  directory below the chosen one is opened without following links; a link
  or non-directory in the way stops the run. (Windows: checked just before
  use, see `SECURITY.md`.)
- **Extracted files are synced** to disk before they appear under their
  name, and their directory afterwards.
- **A source file that changes while being added is not stored.** If it
  grows, shrinks, is modified or replaced during `add`/`migrate`, the
  command fails and nothing is stored. Go stored whatever it read (for a
  file that grew, a truncated copy).
- **`migrate` deletes an original only if it is still the file stored**
  (same inode, size and time), after the record is durable.
- **Deletes are durable in order.** Removing a file syncs the removal of its
  record before deleting its objects, so a crash cannot leave a record
  pointing at deleted objects. A failed sync after a record is already in
  place no longer deletes its objects.
- **Lock errors are reported.** Go let a reader continue without the lock on
  any error; Rust does so only on a read-only filesystem.
- **Stricter records.** A record must have every field, with exactly the
  field names Go writes, and nothing after the JSON. Go also accepted
  differently-cased names, missing fields (as zero) and trailing bytes;
  Go never writes such records, so no existing vault is affected.
- **Key files over 64 KiB** are rejected without reading them whole.

Agent (`unlock`):

- The agent **refuses the key if it cannot protect it**: locking its memory,
  disabling core dumps and (Linux) becoming undumpable must all succeed. Go
  ignored failures there.
- Its environment is stripped of `VAULT_PASSPHRASE` and
  `VAULT_DECOY_PASSPHRASE`; it runs in `/` with standard error closed.
- Expiry no longer waits for the request in progress beyond its deadline,
  and a key is never handed out after expiry.
- `unlock` waits at most ten seconds for the agent to start and kills it on
  failure; the agent removes its socket only if it is still its own.
- **Windows: `unlock` is not available** (Go's agent there had no memory
  protection). Every command asks for the passphrase.

Network (`add URL`, `mirror`):

- Explicit limits, all adjustable: connect 30 s, response headers 60 s,
  whole request 2 h (`add`) or 5 min (`mirror`, per request), download size
  16 GiB (`add`) or 4 GiB in total (`mirror`), 10 redirects, 10 000 mirror
  pages, 16 MiB per HTML or CSS page. Bytes are counted after decompression.
  New flags `--max-bytes`, `--timeout`, `--max-pages`. Go had no limits.
- Redirects go to http or https only; a `mirror` redirect to another host is
  skipped (Go followed it).
- `mirror` resolves links against the final address after redirects and the
  page's `<base href>`; it parses HTML instead of matching a pattern, so it
  rewrites only `href`, `src`, `action` and `poster` on real tags, plus
  `url(...)` in CSS, `<style>` and `style=`, keeping every other byte and
  the original quoting. Text in scripts and comments is no longer touched.
- `mirror` never lets two different URLs in one crawl overwrite each other's
  file; the second is skipped. It exits with status **3** when it stored
  some resources but skipped others (Go always exited 0).
- Proxies follow `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` as in Go; local
  addresses are never proxied.

Command line:

- New option `--workers N` (1–256) on every command.
- `--key`/`--vault` no longer need a home directory when given explicitly.
- Command-line arguments must be valid UTF-8 (Go accepted any bytes, but
  vault names had to be UTF-8 already).
- `ls`/`list` piped into a reader that stops early end quietly with
  status 141, as Go's did by `SIGPIPE`.

Platforms: see `PLATFORMS.md`. Some targets Go built have no stable Rust
equivalent; they are listed there and need a decision before release.

## Unchanged on purpose

Formats, limits (1024-byte names, 1 TiB files, 4 MiB objects, 4096-byte
records, 16 MiB headers, 1 MiB stanzas), Argon2id parameters, the hybrid
suite, filler, decoy behaviour, messages and exit statuses (apart from the
above), the shape of `ls` and `list` output, and the agent protocol.
