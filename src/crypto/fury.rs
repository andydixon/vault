// SPDX-License-Identifier: GPL-3.0-or-later

//! Whole-file Fury encryption: a header wrapping a fresh 32-byte file key,
//! a 16-byte nonce, then the STREAM payload.
//!
//! - header MAC: HMAC-SHA-256 keyed by HKDF-SHA-256(file key, salt none,
//!   info "header"), over the header up to and including "---";
//! - payload key: HKDF-SHA-256(file key, salt = nonce, info "payload").

use super::header::{self, Header, ParseError};
use super::kem::{FILE_KEY_SIZE, Identity, Recipient, UnwrapError};
use super::stream::{self, StreamReader, StreamWriter};
use crate::rng::Rng;
use crate::secret::{SecretArray, SecretVec};
use hkdf::Hkdf;
use hmac::{KeyInit, Mac};
use sha2::Sha256;
use std::io::{self, Read, Write};

pub const NONCE_SIZE: usize = 16;

#[derive(Debug)]
pub enum Error {
    /// No stanza opens with this identity: the file is someone else's.
    NoIdentityMatch,
    Header(ParseError),
    /// A stanza of our suite was malformed.
    Stanza(String),
    BadMac,
    Io(io::Error),
    TooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoIdentityMatch => f.write_str("no identity matched any of the recipients"),
            Error::Header(e) => write!(f, "failed to read header: {e}"),
            Error::Stanza(m) => f.write_str(m),
            Error::BadMac => f.write_str("bad header MAC"),
            Error::Io(e) => write!(f, "{e}"),
            Error::TooLarge => f.write_str("encrypted payload is larger than expected"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

fn header_mac(file_key: &[u8; FILE_KEY_SIZE], h: &Header) -> hmac::Hmac<Sha256> {
    let mut k = SecretArray::<32>::zero();
    Hkdf::<Sha256>::new(None, file_key)
        .expand(b"header", k.expose_mut())
        .expect("32 bytes");
    let mut m = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(k.expose()).expect("any key length");
    m.update(&h.marshal_without_mac());
    m
}

pub fn payload_key(file_key: &[u8; FILE_KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> SecretArray<32> {
    let mut k = SecretArray::<32>::zero();
    Hkdf::<Sha256>::new(Some(nonce), file_key)
        .expand(b"payload", k.expose_mut())
        .expect("32 bytes");
    k
}

/// Builds a header for `recipient` and returns it with the payload key and
/// nonce to use. All randomness is fresh from `rng`.
fn begin(recipient: &Recipient, rng: &mut Rng) -> (Header, [u8; NONCE_SIZE], SecretArray<32>) {
    let mut file_key = SecretArray::<FILE_KEY_SIZE>::zero();
    rng.fill(file_key.expose_mut());
    let mut h = Header {
        recipients: vec![recipient.wrap(file_key.expose(), rng)],
        mac: [0; 32],
    };
    h.mac = header_mac(file_key.expose(), &h).finalize().into_bytes().into();
    let nonce: [u8; NONCE_SIZE] = rng.array();
    let key = payload_key(file_key.expose(), &nonce);
    (h, nonce, key)
}

/// Encrypts a plaintext held in memory, appending the file to `out`.
pub fn encrypt_to(out: &mut Vec<u8>, recipient: &Recipient, plaintext: &[u8], rng: &mut Rng) {
    let (h, nonce, key) = begin(recipient, rng);
    out.extend_from_slice(&h.marshal());
    out.extend_from_slice(&nonce);
    stream::seal_all(key.expose(), plaintext, out);
}

/// Streaming encryption to `dst`; call `finish` on the result.
pub fn encrypt_writer<W: Write>(mut dst: W, recipient: &Recipient, rng: &mut Rng) -> io::Result<StreamWriter<W>> {
    let (h, nonce, key) = begin(recipient, rng);
    h.write_to(&mut dst)?;
    dst.write_all(&nonce)?;
    Ok(StreamWriter::new(key.expose(), dst))
}

/// Go's `decryptHdr`: unwrap with `id`, then check the header MAC in
/// constant time.
fn file_key(h: &Header, id: &Identity) -> Result<SecretArray<FILE_KEY_SIZE>, Error> {
    let fk = match id.unwrap(&h.recipients) {
        Ok(k) => k,
        Err(UnwrapError::NotMine) => return Err(Error::NoIdentityMatch),
        Err(UnwrapError::Malformed(m)) => return Err(Error::Stanza(m)),
    };
    header_mac(fk.expose(), h).verify_slice(&h.mac).map_err(|_| Error::BadMac)?;
    Ok(fk)
}

/// Streaming decryption. Nothing read from the result is authentic until
/// it has returned end of input without error.
pub fn decrypt_reader<R: Read>(src: R, id: &Identity) -> Result<StreamReader<impl Read>, Error> {
    let (h, mut payload) = header::parse(src).map_err(Error::Header)?;
    let fk = file_key(&h, id)?;
    let mut nonce = [0u8; NONCE_SIZE];
    payload
        .read_exact(&mut nonce)
        .map_err(|e| Error::Io(io::Error::new(e.kind(), format!("failed to read nonce: {e}"))))?;
    let key = payload_key(fk.expose(), &nonce);
    Ok(StreamReader::new(key.expose(), payload))
}

/// Decrypts a whole file whose plaintext is at most `max_plaintext` bytes,
/// reading no more than that much ciphertext. The result is fully
/// authenticated, final chunk and end of input included.
pub fn decrypt_bounded<R: Read>(src: R, id: &Identity, max_plaintext: usize) -> Result<SecretVec, Error> {
    let mut buf = SecretVec::with_capacity(max_ciphertext(max_plaintext) + 1);
    decrypt_bounded_into(src, id, max_plaintext, &mut buf)?;
    Ok(buf)
}

/// The largest STREAM payload holding at most `max_plaintext` bytes.
pub fn max_ciphertext(max_plaintext: usize) -> usize {
    max_plaintext + max_plaintext.div_ceil(stream::CHUNK_SIZE).max(1) * stream::TAG_SIZE
}

/// As [`decrypt_bounded`], into a caller-supplied buffer whose capacity
/// must be at least `max_ciphertext(max_plaintext) + 1`. On error the
/// buffer is left empty.
pub fn decrypt_bounded_into<R: Read>(src: R, id: &Identity, max_plaintext: usize, buf: &mut SecretVec) -> Result<(), Error> {
    buf.clear();
    let r = decrypt_into(src, id, max_plaintext, buf);
    if r.is_err() {
        buf.clear();
    }
    r
}

fn decrypt_into<R: Read>(src: R, id: &Identity, max_plaintext: usize, buf: &mut SecretVec) -> Result<(), Error> {
    let (h, mut payload) = header::parse(src).map_err(Error::Header)?;
    let fk = file_key(&h, id)?;
    let mut nonce = [0u8; NONCE_SIZE];
    payload
        .read_exact(&mut nonce)
        .map_err(|e| Error::Io(io::Error::new(e.kind(), format!("failed to read nonce: {e}"))))?;
    let key = payload_key(fk.expose(), &nonce);
    let max_ct = max_ciphertext(max_plaintext);
    buf.resize_within_capacity(max_ct + 1);
    let n = stream::read_full(&mut payload, buf.expose_mut())?;
    if n > max_ct {
        return Err(Error::TooLarge);
    }
    let plain = stream::open_all(key.expose(), &mut buf.expose_mut()[..n]).map_err(|e| Error::Io(e.into()))?;
    buf.resize_within_capacity(plain);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::{
        SUITE_ID,
        tests::{unhex, vectors},
    };
    use crate::crypto::stream::tests::hex;

    fn pattern(n: usize, salt: u8) -> Vec<u8> {
        (0..n).map(|i| (i.wrapping_mul(7) as u8) ^ salt).collect()
    }

    #[test]
    fn header_vectors_match_go() {
        for v in vectors().wrap {
            let raw = unhex(&v.header_hex);
            let (h, _) = header::parse(&raw[..]).unwrap();
            assert_eq!(h.marshal(), raw, "canonical serialisation");
            let fk: [u8; 32] = unhex(&v.file_key).try_into().unwrap();
            assert_eq!(hex(&header_mac(&fk, &h).finalize().into_bytes()), v.mac);
            let id = Identity::from_suite_seed(SUITE_ID, &unhex(&v.master_seed)).unwrap();
            assert_eq!(file_key(&h, &id).unwrap().expose(), &fk);
            let nonce: [u8; 16] = unhex(&v.nonce).try_into().unwrap();
            assert_eq!(hex(payload_key(&fk, &nonce).expose()), v.payload_key);
            // A one-bit change anywhere the MAC covers is caught.
            let mut tampered = h.clone();
            tampered.recipients[0].body[0] ^= 1;
            assert!(file_key(&tampered, &id).is_err());
            let mut wrong_mac = h.clone();
            wrong_mac.mac[31] ^= 1;
            assert!(matches!(file_key(&wrong_mac, &id), Err(Error::BadMac)));
        }
    }

    #[test]
    fn header_parser_agrees_with_go() {
        for (i, c) in vectors().header_cases.into_iter().enumerate() {
            let input = unhex(&c.input_hex);
            let got = header::parse(&input[..]);
            assert_eq!(
                got.is_ok(),
                c.accept,
                "case {i}: {:?}",
                String::from_utf8_lossy(&input[..input.len().min(80)])
            );
            if let Ok((_, mut rest)) = got {
                let mut r = Vec::new();
                rest.read_to_end(&mut r).unwrap();
                assert_eq!(hex(&r), c.rest_hex.unwrap_or_default(), "case {i} payload");
            }
        }
    }

    #[test]
    fn decrypts_go_files() {
        let id = Identity::from_suite_seed(SUITE_ID, &pattern(32, 1)).unwrap();
        for size in [0usize, 1, 65535, 65536, 65537, 131072, 200000] {
            let path = format!("{}/tests/vectors/fury/pattern-{size}.fury", env!("CARGO_MANIFEST_DIR"));
            let data = std::fs::read(&path).unwrap();
            let mut out = Vec::new();
            decrypt_reader(&data[..], &id).unwrap().read_to_end(&mut out).unwrap();
            assert_eq!(out, pattern(size, 0x5a), "{path}");
            let b = decrypt_bounded(&data[..], &id, size).unwrap();
            assert_eq!(b.expose(), &pattern(size, 0x5a)[..]);
            if size > 0 {
                assert!(matches!(
                    decrypt_bounded(&data[..], &id, size - 1),
                    Err(Error::TooLarge) | Err(Error::Io(_))
                ));
            }
            let other = Identity::generate(&mut crate::rng::os());
            assert!(matches!(decrypt_reader(&data[..], &other), Err(Error::NoIdentityMatch)));
        }
    }

    #[test]
    fn round_trip_and_tamper() {
        let id = Identity::generate(&mut crate::rng::os());
        for size in [0usize, 1, 65536, 70000] {
            let p = pattern(size, 3);
            let mut f = Vec::new();
            encrypt_to(&mut f, &id.recipient(), &p, &mut crate::rng::os());
            let mut w = encrypt_writer(Vec::new(), &id.recipient(), &mut crate::rng::os()).unwrap();
            w.write_all(&p).unwrap();
            let f2 = w.finish().unwrap();
            for f in [&f, &f2] {
                assert_eq!(decrypt_bounded(&f[..], &id, size).unwrap().expose(), &p[..]);
                let mut g = f.clone();
                let last = g.len() - 1;
                g[last] ^= 1;
                assert!(decrypt_bounded(&g[..], &id, size).is_err());
                let mut out = Vec::new();
                assert!(decrypt_reader(&g[..], &id).unwrap().read_to_end(&mut out).is_err());
            }
        }
    }

    /// With identical synthetic randomness the in-memory and streaming
    /// encryptors produce identical files.
    #[test]
    fn deterministic_under_test_entropy() {
        let id = Identity::generate(&mut crate::rng::os());
        let e = crate::rng::Entropy::Seeded([9; 32]);
        let p = pattern(200_000, 1);
        let mut a = Vec::new();
        encrypt_to(&mut a, &id.recipient(), &p, &mut e.rng(b"x"));
        let mut w = encrypt_writer(Vec::new(), &id.recipient(), &mut e.rng(b"x")).unwrap();
        w.write_all(&p).unwrap();
        assert_eq!(a, w.finish().unwrap());
    }
}
