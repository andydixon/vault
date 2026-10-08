# Security notes

What vault protects, how, and where the protection stops. See
`docs/COMPATIBILITY.md` for the exact formats.

## What is protected

- **Contents, names, sizes, modes and times** of stored files, against
  anyone who reads the vault directory without the passphrase: everything is
  inside Fury files sealed to a hybrid FrodoKEM-640 + ML-KEM-768 key, so the
  file key stays secret unless both KEMs are broken.
- **Structure**: records are one fixed size; objects are at most 4 MiB and
  padded to power-of-two buckets; object names derive from a secret per-file
  seed, so nothing on disk links a file's objects; every ciphertext and shard
  directory has its timestamps pinned to the epoch; all 256 shards exist from
  the start; `init` adds filler sealed to a discarded key.
- **Integrity**: every byte that is acted on is authenticated (header MAC,
  STREAM tags with a final-chunk flag, no trailing data); an object starts
  with its own ID, so objects cannot be swapped, reordered or replayed under
  another record; `get` publishes output only after the whole file, padding
  and end of file included, has authenticated.
- **Deniability**: the key file always has two equal slots, one possibly
  random; both are always tried; decoy and real files are indistinguishable
  from filler to the other passphrase.

## What is not protected

- The number and total size of ciphertexts, and when the directory changes,
  are visible to whoever stores it.
- A passphrase is only as strong as it is: Argon2id (3 passes, 64 MiB, 4
  lanes) slows guessing, it does not prevent it.
- Anyone who can run code as you while the vault is unlocked (or watch you
  type the passphrase) can read everything.
- Nothing here hides that you use vault.

## Secrets in memory

Passphrases, seeds, private keys, key-encryption keys and plaintext buffers
are held in owned types (`SecretArray`, `SecretVec`, `LockedBuf`) that are
not `Clone`, `Copy`, `Debug` or serialisable, have fixed allocations that
never reallocate, and are cleared with `zeroize` when dropped — on success,
on error and while unwinding from a panic (release builds unwind).

What cannot be cleared, so is not claimed:

- copies the compiler leaves in registers or on the stack;
- copies inside third-party key objects: `chacha20poly1305` cipher states
  (the key schedule), `ml-kem`'s `Seed` passed by value (the decapsulation
  key itself is zeroized on drop with the crate's `zeroize` feature),
  `hmac`/`hkdf` internal states, `argon2` internals other than its working
  memory (which vault allocates and clears itself);
- the passphrase in `$VAULT_PASSPHRASE` (it is in the process environment
  for the process lifetime) and in the terminal driver's buffers;
- anything after `abort`, `kill -9`, a power cut, or once swapped out;
- file data in the OS page cache, and plaintext temporary files on disk
  (below).

None of this is erasure from physical memory.

## The agent

`vault unlock` re-executes the binary as `vault __agent` with
`VAULT_PASSPHRASE` and `VAULT_DECOY_PASSPHRASE` removed from its environment,
no secret in its arguments, its working directory `/` and standard error
closed. It hands over the 34-byte suite ID and seed through a pipe. Before
reading it (straight from the pipe into the locked page, with no
intermediate buffer), the agent:

1. sets the core-dump size limit to zero;
2. on Linux, sets `PR_SET_DUMPABLE` to 0 (no core dumps, no same-user
   `ptrace`, `/proc/PID/mem` or `/proc/PID/environ`) and checks it took;
3. maps a private page, `mlock`s it and, on Linux, marks it
   `MADV_DONTDUMP`, all checked.

Any failure is reported to `unlock` and the agent exits without the key;
there is no fallback to unprotected memory. On other Unix systems (macOS,
the BSDs, illumos) steps 1 and 3 apply; there is no portable equivalent of
`PR_SET_DUMPABLE`, so another process of the same user may be able to read
the agent's memory with a debugger.

The socket lives in a directory that must be owned by you with mode exactly
0700 (refused otherwise); the socket is 0600, checked before readiness. Each
request has a two-second deadline; the expiry deadline is enforced with a
timed `poll`, so it does not depend on another client arriving, and a key
is never handed out after expiry. On exit the agent clears the page and
removes the socket only if it is still its own. `unlock` waits at most ten
seconds for the agent to report and kills it otherwise.

Windows: the agent is not supported (`unlock` says so); every command asks
for the passphrase.

## Filesystem safety

- Output is published with an atomic no-replace primitive
  (`renameat2(RENAME_NOREPLACE)`, `renameatx_np(RENAME_EXCL)`, `link`+`unlink`,
  or `MoveFileExW` without replace), so an existing file, symlink (dangling
  or not) or one created concurrently is never replaced; only vault's own
  temporary file is removed. There is no check-then-rename fallback.
- The temporary output file is mode 0600 until the content has fully
  authenticated; only then are the recorded mode and times applied.
- `get -r` opens each directory below the chosen destination with
  `O_NOFOLLOW|O_DIRECTORY` relative to its parent, so a symlink planted
  inside the destination cannot redirect files elsewhere. On Windows, which
  has no `openat`, each component is checked not to be a link or junction
  just before use; a concurrent swap between check and use is not excluded.
- Writes follow crash-safe order with explicit `fsync` of files and
  directories (Unix): objects before their record; a new record before the
  removal of the one it replaces; a record's removal before its objects'.
  A failure after a record is already in place never deletes its objects.
  Windows has no directory fsync through the APIs used; NTFS journals
  metadata.
- `migrate` checks an original is still the file it stored (device, inode,
  size, time; on Windows only size and time) and then deletes it by name; a
  replacement in the instant between the check and the deletion is not
  excluded. Paths inside the vault directory are refused outright.
- A filesystem with neither `RENAME_NOREPLACE` nor hard links (some FUSE
  mounts, FAT) cannot publish without risking a replace, so `get` fails
  there with a message saying so rather than fall back.
- The vault lock uses the same POSIX `fcntl` locks as the Go version, so
  mixed Go and Rust processes exclude each other. Only a read-only
  filesystem lets a reader proceed without the lock.

## Plaintext on disk

- `vault add URL` and `vault mirror` stream non-HTML downloads to a 0600
  temporary file in `$TMPDIR` before storing them, because the size must be
  known first. On Unix the file is unlinked as soon as it is created, so it
  has no name and disappears even if vault is killed; on other systems it
  is a named file removed on every normal path, including errors. HTML and
  CSS are rewritten in memory. `vault absorb` stores tar
  entries straight from the stream with no temporary file.
- `vault get` writes plaintext where you ask; `vault migrate` deletes the
  originals with `unlink`, which is not secure deletion.

## Network

Downloads verify TLS certificates (rustls with the platform verifier; it is
never disabled), follow at most 10 redirects (http and https only; for
`mirror`, only to the same host), and are bounded by connect, response and
whole-request deadlines and a byte budget counted after decompression. See
`vault(1)` for the defaults and flags.

## Cryptographic implementations

FrodoKEM-640-SHAKE is a port of CIRCL v1.6.4's implementation (constant-time
in the same places: no secret-dependent branches or indices; the
re-encryption check selects the rejection key with a mask). It reproduces
CIRCL's NIST KAT digest. ML-KEM-768 (`ml-kem`), ChaCha20-Poly1305 and
XChaCha20-Poly1305 (`chacha20poly1305`), Argon2id (`argon2`), HKDF, HMAC,
SHA-2 and SHA-3 are RustCrypto crates; TLS is rustls with `ring`. A Rust
rewrite is not stronger cryptography: the algorithms and parameters are
unchanged.

## Reporting

Please report vulnerabilities privately to andy@dixon.cx.
