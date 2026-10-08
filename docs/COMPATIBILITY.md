# Compatibility specification

This is the on-disk and on-wire contract between the Go implementation
(frozen in `oracle/go`, commit `4c1507c`) and the Rust implementation. It is
derived from the Go sources and pinned by vectors the Go oracle generated
(`tests/vectors`, regenerated with `oracle/gen-vectors.sh`). The Rust port is
an implementation migration, not a format migration: nothing here changes,
no data is rekeyed or converted, and no new suite becomes the default.

Each section names the tests that hold the Rust code to it. "Go" below always
means the oracle.

## 1. Key file

| Item | Value |
| --- | --- |
| Encoding | one PEM block, type `VAULT KEY`, standard base64 with padding, 64 columns, as Go's `pem.Encode` |
| Body | exactly 198 bytes: an 18-byte header and two 90-byte slots |
| Header | `VAULTKEY1`, Argon2id time `3` (u32 BE), memory `65536` KiB (u32 BE), lanes `4` (u8) |
| Slot | 16-byte salt, 24-byte XChaCha20-Poly1305 nonce, 34 bytes sealed (u16 BE suite ID, 32-byte master seed), 16-byte tag |
| Slot key | Argon2id v1.3 (passphrase bytes as given, no normalisation, salt, t=3, m=64 MiB, p=4, 32 bytes) |
| Associated data | the 18-byte header |
| Second slot | a decoy identity's slot, or 90 random bytes; which slot is real is random |
| Unlock | Argon2id runs for both slots every time (Rust runs them concurrently); the first slot that opens wins; "incorrect passphrase" if neither |

Accepted framing: optional text before the block (Go's `pem.Decode`), only
whitespace after it, header lines inside the block ignored. Files over 64 KiB
are refused outright (Go would read them, then reject them).

Tests: `keyfile::tests::*` (Argon2id vectors, Go-written key files with and
without decoy open to the Go-recorded seeds, byte-identical PEM re-encoding,
malformed framing, NFC/NFD passphrases differ).

## 2. Hybrid suite `0x0001`, tag `frodo640shake+mlkem768`

- Master seed: 32 bytes. Expansion:
  `HKDF-SHA-256(ikm = seed, salt = none, info = "fury/v1 seed-expand frodo640shake+mlkem768")`,
  read as 48 bytes of FrodoKEM seed then 64 bytes of ML-KEM seed.
- FrodoKEM-640-SHAKE exactly as CIRCL v1.6.4 `kem/frodo/frodo640shake`
  (the round-3 FrodoKEM, not the ISO/eFrodoKEM variants): key seed
  `s(16) || seedSE(16) || z(16)`; public key 9616 bytes (`seedA || pack(B)`);
  private key 19888 bytes (`s || pk || S as u16 LE || H(pk)`); ciphertext 9720
  bytes; 16-byte shared secret; 16-byte encapsulation seed `mu`; implicit
  rejection returns `SHAKE128(ct || s)`.
- ML-KEM-768 (FIPS 203) with seed `d || z`; encapsulation key 1184 bytes,
  expanded decapsulation key 2400 bytes, ciphertext 1088 bytes, 32-byte
  shared secret, implicit rejection.
- Public key: FrodoKEM public key `||` ML-KEM encapsulation key (10800 bytes).
  Private key (for comparison only): FrodoKEM private `||` ML-KEM expanded.
- Wrap: fresh, independent randomness for both encapsulations every time.
  `KEK = HKDF-SHA-256(ikm = ss1 || ss2, salt = none, info = "fury/v1 kek frodo640shake+mlkem768" || ct1 || ct2)`;
  the 32-byte file key is sealed with ChaCha20-Poly1305 under the KEK and an
  all-zero 12-byte nonce. The zero nonce is safe only because each KEK is new
  and used once; the Rust code keeps that sealing function private to the
  suite.
- Stanza: type `frodo640shake+mlkem768`, two arguments
  `base64(ct1)`, `base64(ct2)`, body = 48-byte sealed file key.
- Unwrap: a stanza of another type is "not mine"; wrong argument count,
  bad base64 or wrong ciphertext lengths are fatal for the file; an AEAD
  failure (wrong key) is "not mine". The first stanza that opens wins.

Rust implementation: FrodoKEM is a line-by-line port of CIRCL
(`src/crypto/frodo.rs`) because no maintained Rust crate implements CIRCL's
variant (RustCrypto `frodo-kem` 0.1 implements the salted ISO version with
9752-byte ciphertexts). ML-KEM is RustCrypto `ml-kem` 0.3.2.

Tests: `crypto::frodo::tests::nist_kat_digest` (reproduces the SHA-256
CIRCL checks against the FrodoKEM reference KAT file),
`crypto::kem::tests::{frodo_matches_circl, mlkem_matches_circl,
hybrid_derivation_matches_go, wrap_matches_go_and_unwraps,
fresh_wraps_differ_and_foreign_keys_do_not_match}`.

## 3. Fury header

```text
fury-encryption.org/v1\n
-> TYPE ARG ARG\n                 per stanza; TYPE and ARGs are 1+ bytes of 0x21-0x7e
BODY, 64 base64 columns per line, ending with a line shorter than 64
--- MAC\n                         MAC = base64 of 32 bytes
```

- Base64: standard alphabet, no padding, non-zero trailing bits rejected,
  CR or LF anywhere in an encoded value rejected.
- A body whose encoding fills its last line (the 48-byte wrapped key encodes
  to exactly 64 characters) is followed by an empty line; serialisation is
  canonical and Rust reproduces Go's bytes exactly.
- Limits: 1 MiB per stanza (all its lines), 16 MiB per header; a line must
  end in LF; three bytes of look-ahead decide between a stanza and the
  footer; the payload starts immediately after the footer's LF, with any
  read-ahead returned first.
- MAC: `HMAC-SHA-256(key = HKDF-SHA-256(file key, salt none, info "header"), message = header up to and including "---")`,
  compared in constant time.
- Payload: 16-byte nonce, then STREAM keyed by
  `HKDF-SHA-256(file key, salt = nonce, info "payload")`.

Tests: `crypto::fury::tests::{header_vectors_match_go,
header_parser_agrees_with_go, decrypts_go_files}` (the parser's accept or
reject verdict, and the payload bytes left after the header, match Go on
every case in `crypto.json`), `crypto::header::tests::*`,
`tests/interop_crypto.rs` (Go decrypts files Rust wrote, and rejects
truncated, extended and corrupted ones).

## 4. STREAM

- 64 KiB plaintext chunks; ChaCha20-Poly1305; 16-byte tag per chunk.
- Nonce: 12 bytes, bytes 3..11 the big-endian chunk index, last byte `1`
  on the final chunk only, `0` otherwise.
- Only the final chunk may be short; it may be empty only when it is the
  only chunk (empty plaintext). A plaintext that is an exact multiple of
  64 KiB ends with a full-length final chunk.
- Rejected: no final chunk (truncation), an empty final chunk after
  others, bytes after the final chunk, any chunk failing authentication,
  a payload length no STREAM encoding can have.
- The index never wraps; Rust refuses to go past 2^64 − 1 chunks (Go's
  counter is 88 bits; neither limit is reachable in practice).
- Random access (`StreamReaderAt`) authenticates the final chunk when
  constructed, then any chunk on demand.

Tests: `crypto::stream::tests::*` (Go vectors for sizes around every
boundary, any write/read step sizes, malformations rejected identically by
the streaming, in-memory and random-access readers, concurrency of the
random-access reader, counter overflow).

## 5. Store

- `DIR/.vault` contains exactly `VAULT 2\n`.
- `DIR/records/xx/ID` and `DIR/objects/xx/ID`: `ID` is 16 bytes as
  lowercase hex, `xx` its first byte; all 256 shards of both exist after
  `init`. Entries whose names are not exactly that form, or are in the
  wrong shard, are ignored.
- Every ciphertext, every shard and both top directories have access and
  modification times pinned to the Unix epoch; removals re-pin the shard.
- Record: a Fury file whose plaintext is exactly 4096 bytes: a u32 BE JSON
  length (≤ 4092), the JSON, random padding. JSON is Go's `encoding/json`
  output for `{"name","seed","size","mode","modified","added"}`: HTML
  characters and U+2028/2029 escaped, times RFC 3339 with up to nine
  fractional digits, trailing zeros removed, `Z`. Rust writes it
  byte-identically.
- Validation on read: name valid (below), seed 64 lowercase hex characters,
  size 0..=1 TiB, both times valid RFC 3339; unknown fields refused.
- Names: non-empty UTF-8, ≤ 1024 bytes, already clean (Go `path.Clean`),
  relative, not `.`/`..`/`../…`, no backslash, no control characters.
- Object IDs: `HMAC-SHA-256(key = seed, msg = index as big-endian i64)[:16]`.
- Objects: plaintext = own ID (16 bytes), then up to `4 MiB − 16` file
  bytes, then random padding to the next power of two from 64 KiB to 4 MiB.
  An empty file still has one object. These sizes are plaintext; the
  ciphertext adds the header (~14.6 KB) and 16 bytes per 64 KiB.
- Reading an object checks: it opens, its first 16 bytes are its ID, its
  length is exactly the padded size for its part, and the whole STREAM
  (final chunk, end of file) authenticates.
- Records the key cannot open (no stanza matches) are skipped silently;
  ones that open but are malformed are reported and skipped.
- Duplicates (an interrupted replace) are ordered newest `added` first; the
  next write of that name removes them all.
- Filler: `init` writes 8–32 entries (or more, to reach `--filler`) of
  log-uniform sizes from 1 KiB to `clamp(target/8, 4 MiB, 1 GiB)`, sealed to
  a throwaway key, through the same code as `add`.

Tests: `store::types::tests::*` (names, object IDs, padded sizes, object
counts, record JSON byte-identical to Go), `store::tests::reads_go_vault`
(the oracle's fixture vault: real files, decoy file, foreign record),
`store::tests::*`, `tests/cli.rs` lifecycle tests in both directions.

## 6. Locks

`DIR/.lock`, created mode 0600. Unix: POSIX `fcntl` record locks over the
whole file (`F_SETLK` then `F_SETLKW`), shared for readers, exclusive for
writers, released by the kernel when the process dies. Windows:
`LockFileEx` on byte 0, length 1. Other systems: an `O_EXCL` lock file.
Tests: `tests/cli.rs::lock_*` (Rust waits for Go, Go waits for Rust, both
proceed after the holder is killed).

## 7. Agent

Socket `$XDG_RUNTIME_DIR` (else `$TMPDIR`, else `/tmp`) `/vault-UID/agent-`
followed by the first 8 bytes of SHA-256 of the key file's absolute path
(Go `filepath.Abs`, including its use of `$PWD`) in hex. The directory must
be the user's own with mode exactly 0700. One request per connection: `g`
→ 34 bytes (u16 BE suite ID, seed); `q` → the agent wipes the key and
closes. Two-second deadline per request. Tests:
`tests/cli.rs::agent_*` (Rust client with Go agent and the reverse).

## 8. What is deliberately not identical

See `docs/MIGRATION.md` for the full list of intentional behaviour changes.
None of them alters a byte that is written to the vault or the key file
beyond what the Go format already allows (fresh randomness, timestamps).
