// SPDX-License-Identifier: GPL-3.0-or-later

//! The passphrase-protected key file, byte-compatible with the Go version.
//!
//! A PEM block of type `VAULT KEY` holds 198 bytes: an 18-byte header
//! (`VAULTKEY1`, Argon2id time 3 and memory 65536 KiB as big-endian u32s,
//! and 4 lanes as one byte) and two 90-byte slots. A slot is a 16-byte
//! salt, a 24-byte XChaCha20-Poly1305 nonce and the sealed big-endian suite
//! ID and 32-byte master seed, with the header as associated data and the
//! key Argon2id(passphrase, salt). The second slot is a decoy identity or
//! random bytes, and which slot is real is random, so the file says nothing
//! about whether a decoy exists. Unlocking always runs Argon2id for both
//! slots, so timing does not reveal which one matched.

use crate::crypto::kem::{self, Identity};
use crate::rng::Rng;
use crate::secret::{SecretArray, SecretVec};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::Engine;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use std::io::Write;
use std::path::Path;
use zeroize::Zeroize;

pub const PEM_TYPE: &str = "VAULT KEY";
const MAGIC: &[u8] = b"VAULTKEY1";
const ARGON_TIME: u32 = 3;
const ARGON_MEMORY: u32 = 64 * 1024; // KiB
const ARGON_THREADS: u8 = 4;
const SALT: usize = 16;
const XNONCE: usize = 24;
const SLOT_PLAIN: usize = 2 + kem::SEED_SIZE;
pub const SLOT_SIZE: usize = SALT + XNONCE + SLOT_PLAIN + 16;
pub const HEADER_SIZE: usize = 18;
pub const BODY_SIZE: usize = HEADER_SIZE + 2 * SLOT_SIZE;
/// Key files are a few hundred bytes; anything this large is not one.
const MAX_FILE: u64 = 64 << 10;

pub fn header() -> [u8; HEADER_SIZE] {
    let mut h = [0u8; HEADER_SIZE];
    h[..9].copy_from_slice(MAGIC);
    h[9..13].copy_from_slice(&ARGON_TIME.to_be_bytes());
    h[13..17].copy_from_slice(&ARGON_MEMORY.to_be_bytes());
    h[17] = ARGON_THREADS;
    h
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    NotAKeyFile,
    IncorrectPassphrase,
    Io(String),
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotAKeyFile => f.write_str("not a vault key file"),
            Error::IncorrectPassphrase => f.write_str("incorrect passphrase"),
            Error::Io(m) | Error::Invalid(m) => f.write_str(m),
        }
    }
}

/// Argon2id(passphrase, salt) with the file's fixed parameters. The
/// passphrase bytes are used exactly as given: no normalisation.
pub fn slot_key(passphrase: &[u8], salt: &[u8]) -> SecretArray<32> {
    let params = Params::new(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS as u32, Some(32)).expect("valid parameters");
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut blocks = vec![Block::default(); a.params().block_count()];
    let mut key = SecretArray::<32>::zero();
    let r = a.hash_password_into_with_memory(passphrase, salt, key.expose_mut(), &mut blocks[..]);
    // The working memory is derived from the passphrase; clear all 64 MiB.
    for b in blocks.iter_mut() {
        b.zeroize();
    }
    r.expect("argon2 inputs within limits");
    key
}

fn seal_slot(id: &Identity, passphrase: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut slot = vec![0u8; SALT + XNONCE];
    rng.fill(&mut slot);
    let key = slot_key(passphrase, &slot[..SALT]);
    let aead = XChaCha20Poly1305::new(key.expose().into());
    let mut plain = SecretVec::with_capacity(SLOT_PLAIN);
    plain.extend_within_capacity(&id.suite_id().to_be_bytes());
    plain.extend_within_capacity(id.seed());
    let nonce = XNonce::try_from(&slot[SALT..]).expect("nonce size");
    let tag = aead
        .encrypt_inout_detached(&nonce, &header(), plain.expose_mut().into())
        .expect("small message");
    slot.extend_from_slice(plain.expose());
    slot.extend_from_slice(&tag);
    slot
}

/// Opens one slot, or None if the passphrase does not open it.
fn open_slot(slot: &[u8], passphrase: &[u8]) -> Option<SecretVec> {
    let key = slot_key(passphrase, &slot[..SALT]);
    let aead = XChaCha20Poly1305::new(key.expose().into());
    let nonce = XNonce::try_from(&slot[SALT..SALT + XNONCE]).expect("nonce size");
    let ct = &slot[SALT + XNONCE..];
    let mut plain = SecretVec::zeroed(SLOT_PLAIN);
    plain.expose_mut().copy_from_slice(&ct[..SLOT_PLAIN]);
    let tag = Tag::try_from(&ct[SLOT_PLAIN..]).expect("tag size");
    aead.decrypt_inout_detached(&nonce, &header(), plain.expose_mut().into(), &tag)
        .ok()?;
    Some(plain)
}

/// The PEM text for a key file body, exactly as Go's `pem.Encode` writes it.
pub fn encode_pem(body: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(body);
    let mut s = format!("-----BEGIN {PEM_TYPE}-----\n");
    for line in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).expect("ascii"));
        s.push('\n');
    }
    s.push_str(&format!("-----END {PEM_TYPE}-----\n"));
    s
}

/// The block body if `data` is one `VAULT KEY` PEM block, optionally with
/// text before it (as Go's `pem.Decode` allows) and only whitespace after.
pub fn decode_pem(data: &[u8]) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {PEM_TYPE}-----");
    let end = format!("-----END {PEM_TYPE}-----");
    let start = if data.starts_with(b"-----BEGIN ") {
        0
    } else {
        find(data, b"\n-----BEGIN ")? + 1
    };
    let mut lines = data[start..].split_inclusive(|&c| c == b'\n');
    let first = lines.next()?;
    if trim_right(first) != begin.as_bytes() {
        return None;
    }
    let mut b64 = Vec::new();
    let mut after = None;
    let mut consumed = start + first.len();
    for line in lines.by_ref() {
        consumed += line.len();
        let t = trim_right(line);
        if t == end.as_bytes() {
            after = Some(consumed);
            break;
        }
        if t.contains(&b':') {
            // A PEM header line; Go accepts and ignores them.
            continue;
        }
        b64.extend(t.iter().filter(|c| !matches!(c, b' ' | b'\t')));
    }
    let after = after?;
    if !data[after..].iter().all(|c| c.is_ascii_whitespace()) {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(&b64).ok()
}

fn trim_right(l: &[u8]) -> &[u8] {
    let mut e = l.len();
    while e > 0 && matches!(l[e - 1], b' ' | b'\t' | b'\r' | b'\n') {
        e -= 1;
    }
    &l[..e]
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Builds a key file body: one slot for `passphrase`, the other for
/// `decoy` or random bytes if it is empty, in random order.
pub fn new_body(passphrase: &[u8], decoy: &[u8], rng: &mut Rng) -> Vec<u8> {
    let real_slot = (rng.array::<1>()[0] & 1) as usize;
    let mut slots: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    for (i, pass) in [passphrase, decoy].into_iter().enumerate() {
        let idx = real_slot ^ i;
        if pass.is_empty() {
            let mut r = vec![0u8; SLOT_SIZE];
            rng.fill(&mut r);
            slots[idx] = r;
            continue;
        }
        let id = Identity::generate(rng);
        slots[idx] = seal_slot(&id, pass, rng);
    }
    let mut body = header().to_vec();
    body.extend_from_slice(&slots[0]);
    body.extend_from_slice(&slots[1]);
    body
}

/// Creates a new key file at `path`, refusing to replace an existing one.
pub fn write(path: &Path, passphrase: &[u8], decoy: &[u8]) -> Result<(), Error> {
    let body = new_body(passphrase, decoy, &mut crate::rng::os());
    let pem = encode_pem(&body);
    let ioerr = |op: &str, e: std::io::Error| Error::Io(crate::util::io_msg(op, path, &e));
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        crate::platform::fs::create_private_dir_all(parent).map_err(|e| Error::Io(crate::util::io_msg("mkdir", parent, &e)))?;
    }
    let mut f = crate::platform::fs::create_new_private(path).map_err(|e| ioerr("open", e))?;
    if let Err(e) = f.write_all(pem.as_bytes()).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(ioerr("write", e));
    }
    drop(f);
    if let Some(parent) = path.parent() {
        let _ = crate::platform::fs::sync_dir(if parent.as_os_str().is_empty() { Path::new(".") } else { parent });
    }
    Ok(())
}

/// Checks a key file body's framing, returning its two slots.
pub fn parse_body(body: &[u8]) -> Result<[&[u8]; 2], Error> {
    if body.len() != BODY_SIZE || body[..HEADER_SIZE] != header() {
        return Err(Error::NotAKeyFile);
    }
    let s = &body[HEADER_SIZE..];
    Ok([&s[..SLOT_SIZE], &s[SLOT_SIZE..]])
}

/// The identity whose slot `passphrase` opens. Both slots are always tried.
pub fn unlock_body(body: &[u8], passphrase: &[u8]) -> Result<Identity, Error> {
    let slots = parse_body(body)?;
    // Both Argon2id runs happen whatever the outcome, concurrently, so the
    // time taken does not depend on which slot (if any) matched.
    let opened: Vec<Option<SecretVec>> = std::thread::scope(|s| {
        let h: Vec<_> = slots.iter().map(|slot| s.spawn(move || open_slot(slot, passphrase))).collect();
        h.into_iter().map(|h| h.join().expect("argon2 thread")).collect()
    });
    if let Some(plain) = opened.into_iter().flatten().next() {
        let p = plain.expose();
        let suite = u16::from_be_bytes([p[0], p[1]]);
        return Identity::from_suite_seed(suite, &p[2..]).map_err(Error::Invalid);
    }
    Err(Error::IncorrectPassphrase)
}

pub fn read_body(path: &Path) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(|e| Error::Io(crate::util::io_msg("open", path, &e)))?;
    let mut data = Vec::new();
    f.take(MAX_FILE + 1)
        .read_to_end(&mut data)
        .map_err(|e| Error::Io(crate::util::io_msg("read", path, &e)))?;
    if data.len() as u64 > MAX_FILE {
        return Err(Error::NotAKeyFile);
    }
    let body = decode_pem(&data).ok_or(Error::NotAKeyFile)?;
    parse_body(&body)?;
    Ok(body)
}

pub fn unlock(path: &Path, passphrase: &[u8]) -> Result<Identity, Error> {
    unlock_body(&read_body(path)?, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::tests::unhex;
    use crate::crypto::stream::tests::hex;
    use serde_json::Value;

    fn store_vectors() -> Value {
        serde_json::from_str(include_str!("../tests/vectors/store.json")).unwrap()
    }

    #[test]
    fn argon2id_matches_go() {
        let v = store_vectors();
        for c in v["argon2id"].as_array().unwrap() {
            let k = slot_key(&unhex(c["passphrase_hex"].as_str().unwrap()), &unhex(c["salt"].as_str().unwrap()));
            assert_eq!(hex(k.expose()), c["key"].as_str().unwrap());
        }
        assert_eq!(hex(&header()), v["key_header_hex"].as_str().unwrap());
    }

    #[test]
    fn opens_go_key_files() {
        let v = store_vectors();
        for (name, slots) in v["keys"].as_object().unwrap() {
            let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
            let body = read_body(Path::new(&path)).unwrap();
            assert_eq!(body.len(), 198);
            for (_, s) in slots.as_object().unwrap() {
                let id = unlock_body(&body, s["passphrase"].as_str().unwrap().as_bytes()).unwrap();
                assert_eq!(hex(id.seed()), s["seed"].as_str().unwrap());
                assert_eq!(id.suite_id() as u64, s["suite"].as_u64().unwrap());
            }
            assert_eq!(unlock_body(&body, b"wrong").err(), Some(Error::IncorrectPassphrase));
            // Re-encoding reproduces Go's PEM text exactly.
            assert_eq!(encode_pem(&body).as_bytes(), &std::fs::read(&path).unwrap()[..]);
        }
    }

    #[test]
    fn new_key_files_round_trip() {
        let body = new_body(b"real", b"decoy", &mut crate::rng::os());
        let a = unlock_body(&body, b"real").unwrap();
        let b = unlock_body(&body, b"decoy").unwrap();
        assert_ne!(a.seed(), b.seed());
        assert!(unlock_body(&body, b"other").is_err());
        let solo = new_body(b"real", b"", &mut crate::rng::os());
        assert_eq!(solo.len(), body.len());
        assert!(unlock_body(&solo, b"").is_err());
        // Passphrases are bytes: no normalisation of composed/decomposed é.
        let nfc = "caf\u{e9}".as_bytes();
        let nfd = "cafe\u{301}".as_bytes();
        let k = new_body(nfc, b"", &mut crate::rng::os());
        assert!(unlock_body(&k, nfc).is_ok());
        assert!(unlock_body(&k, nfd).is_err());
    }

    #[test]
    fn malformed_key_files() {
        let body = new_body(b"p", b"", &mut crate::rng::os());
        let pem = encode_pem(&body);
        assert_eq!(decode_pem(pem.as_bytes()).unwrap(), body);
        assert_eq!(decode_pem(format!("junk\n{pem}\n  \n").as_bytes()).unwrap(), body);
        assert!(decode_pem(format!("{pem}x").as_bytes()).is_none());
        assert!(decode_pem(pem.replace("VAULT KEY", "VAULT KEX").as_bytes()).is_none());
        assert!(decode_pem(pem.replace("-----END", "-----FIN").as_bytes()).is_none());
        let mut short = body.clone();
        short.pop();
        assert_eq!(parse_body(&short).err(), Some(Error::NotAKeyFile));
        let mut wrong = body.clone();
        wrong[17] = 1; // a different Argon2 lane count
        assert_eq!(parse_body(&wrong).err(), Some(Error::NotAKeyFile));
        let mut tampered = body.clone();
        tampered[HEADER_SIZE + SALT + XNONCE] ^= 1;
        tampered[HEADER_SIZE + SLOT_SIZE + SALT + XNONCE] ^= 1;
        assert_eq!(unlock_body(&tampered, b"p").err(), Some(Error::IncorrectPassphrase));
    }
}
