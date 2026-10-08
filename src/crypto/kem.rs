// SPDX-License-Identifier: GPL-3.0-or-later

//! The hybrid FrodoKEM-640-SHAKE + ML-KEM-768 suite (ID 0x0001, stanza tag
//! `frodo640shake+mlkem768`), as the Go `pqcrypt` package defines it.
//!
//! - Keys: a 32-byte master seed is expanded with
//!   HKDF-SHA-256(seed, salt = none, info = "fury/v1 seed-expand " + tag)
//!   into a 48-byte FrodoKEM seed followed by a 64-byte ML-KEM seed (d||z).
//! - Wrap: both KEMs encapsulate with fresh randomness; the KEK is
//!   HKDF-SHA-256(ss1 || ss2, salt = none, info = "fury/v1 kek " + tag ||
//!   ct1 || ct2), and the 32-byte file key is sealed under it with
//!   ChaCha20-Poly1305 and an all-zero nonce. The zero nonce is safe only
//!   because every KEK is fresh and used once; nothing else may use
//!   [`seal_once`].

use super::frodo;
use super::header::{self, Stanza};
use crate::rng::Rng;
use crate::secret::SecretArray;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const SUITE_ID: u16 = 0x0001;
pub const TAG: &str = "frodo640shake+mlkem768";
pub const SEED_SIZE: usize = 32;
pub const FILE_KEY_SIZE: usize = 32;
const MLKEM_PK: usize = 1184;
const MLKEM_CT: usize = 1088;
const MLKEM_SEED: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = frodo::PUBLIC_KEY_SIZE + MLKEM_PK;

/// Why a stanza could not be unwrapped.
#[derive(Debug, PartialEq, Eq)]
pub enum UnwrapError {
    /// The stanza is not for this identity (wrong suite, or the file key
    /// does not open): try the next stanza or identity.
    NotMine,
    /// The stanza claims this suite but is malformed; Go treats this as
    /// fatal for the whole file.
    Malformed(String),
}

fn hkdf_expand(ikm: &[u8], salt: Option<&[u8]>, info: &[&[u8]], out: &mut [u8]) {
    let h = Hkdf::<Sha256>::new(salt, ikm);
    h.expand_multi_info(info, out).expect("hkdf output length within limits");
}

/// The recipient: FrodoKEM public key || ML-KEM encapsulation key.
pub struct Recipient {
    bytes: Vec<u8>,
    frodo: frodo::PublicKey,
    mlkem: EncapsulationKey<MlKem768>,
}

impl Recipient {
    pub fn from_bytes(pub_key: &[u8]) -> Result<Self, String> {
        if pub_key.len() != PUBLIC_KEY_SIZE {
            return Err(format!("invalid {TAG} public key size"));
        }
        let frodo = frodo::PublicKey::from_bytes(&pub_key[..frodo::PUBLIC_KEY_SIZE]).ok_or("invalid FrodoKEM public key")?;
        let ek = ml_kem::kem::Key::<EncapsulationKey<MlKem768>>::try_from(&pub_key[frodo::PUBLIC_KEY_SIZE..])
            .map_err(|_| "invalid ML-KEM public key")?;
        let mlkem = EncapsulationKey::<MlKem768>::new(&ek).map_err(|_| "invalid ML-KEM public key")?;
        Ok(Recipient {
            bytes: pub_key.to_vec(),
            frodo,
            mlkem,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Wraps `file_key` with fresh encapsulations drawn from `rng`.
    pub fn wrap(&self, file_key: &[u8; FILE_KEY_SIZE], rng: &mut Rng) -> Stanza {
        let mut mu = Zeroizing::new([0u8; frodo::ENCAPSULATION_SEED_SIZE]);
        rng.fill(&mut mu[..]);
        let mut m = Zeroizing::new([0u8; 32]);
        rng.fill(&mut m[..]);
        self.wrap_with(file_key, &mu, &m)
    }

    fn wrap_with(&self, file_key: &[u8; FILE_KEY_SIZE], mu: &[u8; 16], m: &[u8; 32]) -> Stanza {
        let (ct1, mut ss1) = self.frodo.encapsulate(mu);
        let (ct2, ss2) = self.mlkem.encapsulate_deterministic(&(*m).into());
        let mut ss2 = Zeroizing::new(ss2);
        let kek = derive_kek(&ss1, &ss2[..], &ct1, &ct2[..]);
        ss1.zeroize();
        ss2.zeroize();
        let body = seal_once(&kek, file_key);
        Stanza {
            typ: TAG.into(),
            args: vec![header::encode(&ct1), header::encode(&ct2[..])],
            body,
        }
    }
}

/// HKDF over both shared secrets, binding both ciphertexts.
fn derive_kek(ss1: &[u8], ss2: &[u8], ct1: &[u8], ct2: &[u8]) -> SecretArray<32> {
    let mut secret = Zeroizing::new([0u8; frodo::SHARED_KEY_SIZE + 32]);
    secret[..frodo::SHARED_KEY_SIZE].copy_from_slice(ss1);
    secret[frodo::SHARED_KEY_SIZE..].copy_from_slice(ss2);
    let label = format!("fury/v1 kek {TAG}");
    let mut kek = SecretArray::<32>::zero();
    hkdf_expand(&secret[..], None, &[label.as_bytes(), ct1, ct2], kek.expose_mut());
    kek
}

/// ChaCha20-Poly1305 under an all-zero nonce, for a key used exactly once.
fn seal_once(kek: &SecretArray<32>, file_key: &[u8; FILE_KEY_SIZE]) -> Vec<u8> {
    let mut k = Key::from(*kek.expose());
    let aead = ChaCha20Poly1305::new(&k);
    k.zeroize();
    let mut body = file_key.to_vec();
    let tag = aead
        .encrypt_inout_detached(&Nonce::default(), &[], body.as_mut_slice().into())
        .expect("32 bytes fit");
    body.extend_from_slice(&tag);
    body
}

fn open_once(kek: &SecretArray<32>, body: &[u8]) -> Option<SecretArray<FILE_KEY_SIZE>> {
    if body.len() != FILE_KEY_SIZE + 16 {
        return None;
    }
    let mut k = Key::from(*kek.expose());
    let aead = ChaCha20Poly1305::new(&k);
    k.zeroize();
    let mut out = SecretArray::<FILE_KEY_SIZE>::zero();
    out.expose_mut().copy_from_slice(&body[..FILE_KEY_SIZE]);
    let tag = Tag::try_from(&body[FILE_KEY_SIZE..]).ok()?;
    aead.decrypt_inout_detached(&Nonce::default(), &[], (&mut out.expose_mut()[..]).into(), &tag)
        .ok()?;
    Some(out)
}

/// A private identity derived from a master seed. It owns the seed and
/// both expanded private keys; dropping it clears what this crate owns
/// (see `crate::secret` for the limits of that). There is no way to use an
/// identity after [`Identity::close`] or drop:
///
/// ```compile_fail
/// let id = vault::crypto::kem::Identity::generate(&mut vault::rng::os());
/// id.close();
/// let _ = id.seed(); // use of a moved value
/// ```
pub struct Identity {
    seed: SecretArray<SEED_SIZE>,
    frodo: frodo::PrivateKey,
    mlkem: Box<DecapsulationKey<MlKem768>>,
    recipient_bytes: Vec<u8>,
}

impl Identity {
    pub fn generate(rng: &mut Rng) -> Self {
        let mut seed = SecretArray::<SEED_SIZE>::zero();
        rng.fill(seed.expose_mut());
        Self::from_seed(seed)
    }

    /// Derives the identity of `suite` from its master seed.
    pub fn from_suite_seed(suite: u16, seed: &[u8]) -> Result<Self, String> {
        if suite != SUITE_ID {
            return Err(format!("unknown suite id {suite:#06x}"));
        }
        let s = SecretArray::<SEED_SIZE>::from_slice(seed).ok_or_else(|| format!("invalid seed size {} for suite {TAG}", seed.len()))?;
        Ok(Self::from_seed(s))
    }

    pub fn from_seed(seed: SecretArray<SEED_SIZE>) -> Self {
        let mut expanded = Zeroizing::new([0u8; frodo::KEY_SEED_SIZE + MLKEM_SEED]);
        let info = format!("fury/v1 seed-expand {TAG}");
        hkdf_expand(seed.expose(), None, &[info.as_bytes()], &mut expanded[..]);
        let mut fseed = Zeroizing::new([0u8; frodo::KEY_SEED_SIZE]);
        fseed.copy_from_slice(&expanded[..frodo::KEY_SEED_SIZE]);
        let frodo = frodo::PrivateKey::derive(&fseed);
        // ml-kem takes the seed by value (a stack copy we cannot clear) and
        // keeps it, zeroizing it on drop.
        let mut mseed = ml_kem::Seed::default();
        mseed.copy_from_slice(&expanded[frodo::KEY_SEED_SIZE..]);
        let mlkem = Box::new(DecapsulationKey::<MlKem768>::from_seed(mseed));
        mseed.zeroize();
        let mut recipient_bytes = frodo.public().to_bytes();
        recipient_bytes.extend_from_slice(&mlkem.encapsulation_key().to_bytes());
        Identity {
            seed,
            frodo,
            mlkem,
            recipient_bytes,
        }
    }

    pub fn suite_id(&self) -> u16 {
        SUITE_ID
    }

    /// The master seed: secret-equivalent to the whole identity.
    pub fn seed(&self) -> &[u8; SEED_SIZE] {
        self.seed.expose()
    }

    pub fn recipient(&self) -> Recipient {
        Recipient::from_bytes(&self.recipient_bytes).expect("derived key is valid")
    }

    pub fn recipient_bytes(&self) -> &[u8] {
        &self.recipient_bytes
    }

    /// The private key bytes as Go serialises them (FrodoKEM || ML-KEM
    /// expanded), for compatibility checks only.
    #[allow(deprecated)]
    pub fn private_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        use ml_kem::ExpandedKeyEncoding;
        let mut v = self.frodo.to_bytes();
        let mut m = self.mlkem.to_expanded_bytes();
        v.extend_from_slice(&m);
        m.zeroize();
        v
    }

    pub fn close(self) {}

    /// Go's `unwrap` for one stanza.
    pub fn unwrap_stanza(&self, s: &Stanza) -> Result<SecretArray<FILE_KEY_SIZE>, UnwrapError> {
        if s.typ != TAG {
            return Err(UnwrapError::NotMine);
        }
        if s.args.len() != 2 {
            return Err(UnwrapError::Malformed(format!("invalid {TAG} stanza: expected 2 arguments")));
        }
        let ct1 = header::decode(s.args[0].as_bytes()).map_err(|e| UnwrapError::Malformed(format!("invalid FrodoKEM ciphertext: {e}")))?;
        let ct2 = header::decode(s.args[1].as_bytes()).map_err(|e| UnwrapError::Malformed(format!("invalid ML-KEM ciphertext: {e}")))?;
        if ct1.len() != frodo::CIPHERTEXT_SIZE || ct2.len() != MLKEM_CT {
            return Err(UnwrapError::Malformed("encrypted value has unexpected length".into()));
        }
        let mut ss1 = self.frodo.decapsulate(&ct1).expect("length checked");
        let ct2a = ml_kem::Ciphertext::<MlKem768>::try_from(&ct2[..]).expect("length checked");
        let mut ss2 = self.mlkem.decapsulate(&ct2a);
        // Both KEMs reject implicitly: a key mismatch shows up as a wrong
        // KEK, which the AEAD below detects.
        let kek = derive_kek(&ss1, &ss2[..], &ct1, &ct2);
        ss1.zeroize();
        ss2.zeroize();
        open_once(&kek, &s.body).ok_or(UnwrapError::NotMine)
    }

    /// Go's `multiUnwrap`: the first stanza that opens wins; a malformed
    /// stanza of this suite stops the search.
    pub fn unwrap(&self, stanzas: &[Stanza]) -> Result<SecretArray<FILE_KEY_SIZE>, UnwrapError> {
        for s in stanzas {
            match self.unwrap_stanza(s) {
                Err(UnwrapError::NotMine) => continue,
                r => return r,
            }
        }
        Err(UnwrapError::NotMine)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::stream::tests::hex;
    use serde::Deserialize;
    use sha2::Digest;

    pub fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn sha(b: &[u8]) -> String {
        hex(&sha2::Sha256::digest(b))
    }

    #[derive(Deserialize)]
    pub struct Crypto {
        pub frodo640shake: Vec<KemV>,
        pub mlkem768: Vec<KemV>,
        pub hybrid: Vec<HybridV>,
        pub wrap: Vec<WrapV>,
        pub header_cases: Vec<HeaderCase>,
    }
    #[derive(Deserialize)]
    pub struct KemV {
        seed: String,
        pub_sha256: String,
        priv_sha256: String,
        encap_seed: String,
        ct_sha256: String,
        ss: String,
        reject_flip_index: usize,
        reject_ss: String,
    }
    #[derive(Deserialize)]
    pub struct HybridV {
        master_seed: String,
        pub_sha256: String,
        priv_sha256: String,
        pub_prefix: String,
    }
    #[derive(Deserialize)]
    pub struct WrapV {
        pub master_seed: String,
        frodo_encap_seed: String,
        mlkem_encap_seed: String,
        pub file_key: String,
        kek: String,
        pub header_hex: String,
        pub mac: String,
        pub nonce: String,
        pub payload_key: String,
        stanza_arg0_sha256: String,
        stanza_body: String,
    }
    #[derive(Deserialize)]
    pub struct HeaderCase {
        pub input_hex: String,
        pub accept: bool,
        pub rest_hex: Option<String>,
    }

    pub fn vectors() -> Crypto {
        serde_json::from_str(include_str!("../../tests/vectors/crypto.json")).unwrap()
    }

    #[test]
    fn frodo_matches_circl() {
        for v in vectors().frodo640shake {
            let seed: [u8; frodo::KEY_SEED_SIZE] = unhex(&v.seed).try_into().unwrap();
            let sk = frodo::PrivateKey::derive(&seed);
            let pk = sk.public().to_bytes();
            assert_eq!(sha(&pk), v.pub_sha256);
            assert_eq!(sha(&sk.to_bytes()), v.priv_sha256);
            let pk2 = frodo::PublicKey::from_bytes(&pk).unwrap();
            let mu: [u8; 16] = unhex(&v.encap_seed).try_into().unwrap();
            let (ct, ss) = pk2.encapsulate(&mu);
            assert_eq!(sha(&ct), v.ct_sha256);
            assert_eq!(hex(&ss), v.ss);
            assert_eq!(hex(&sk.decapsulate(&ct).unwrap()), v.ss);
            let mut bad = ct.clone();
            bad[v.reject_flip_index] ^= 1;
            assert_eq!(hex(&sk.decapsulate(&bad).unwrap()), v.reject_ss, "implicit rejection");
        }
    }

    #[test]
    #[allow(deprecated)]
    fn mlkem_matches_circl() {
        use ml_kem::ExpandedKeyEncoding;
        for v in vectors().mlkem768 {
            let mut seed = ml_kem::Seed::default();
            seed.copy_from_slice(&unhex(&v.seed));
            let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
            let ek = dk.encapsulation_key();
            assert_eq!(sha(&ek.to_bytes()), v.pub_sha256);
            assert_eq!(sha(&dk.to_expanded_bytes()), v.priv_sha256);
            let m: [u8; 32] = unhex(&v.encap_seed).try_into().unwrap();
            let (ct, ss) = ek.encapsulate_deterministic(&m.into());
            assert_eq!(sha(&ct), v.ct_sha256);
            assert_eq!(hex(&ss), v.ss);
            let mut bad = ct;
            bad[v.reject_flip_index] ^= 1;
            assert_eq!(hex(&dk.decapsulate(&bad)), v.reject_ss, "implicit rejection");
        }
    }

    #[test]
    fn hybrid_derivation_matches_go() {
        for v in vectors().hybrid {
            let id = Identity::from_suite_seed(SUITE_ID, &unhex(&v.master_seed)).unwrap();
            assert_eq!(sha(id.recipient_bytes()), v.pub_sha256);
            assert_eq!(hex(&id.recipient_bytes()[..64]), v.pub_prefix);
            assert_eq!(sha(&id.private_key_bytes()), v.priv_sha256);
        }
        assert!(Identity::from_suite_seed(2, &[0; 32]).is_err());
        assert!(Identity::from_suite_seed(SUITE_ID, &[0; 31]).is_err());
    }

    #[test]
    fn wrap_matches_go_and_unwraps() {
        for v in vectors().wrap {
            let id = Identity::from_suite_seed(SUITE_ID, &unhex(&v.master_seed)).unwrap();
            let fk: [u8; 32] = unhex(&v.file_key).try_into().unwrap();
            let mu: [u8; 16] = unhex(&v.frodo_encap_seed).try_into().unwrap();
            let m: [u8; 32] = unhex(&v.mlkem_encap_seed).try_into().unwrap();
            let st = id.recipient().wrap_with(&fk, &mu, &m);
            assert_eq!(sha(st.args[0].as_bytes()), v.stanza_arg0_sha256);
            assert_eq!(hex(&st.body), v.stanza_body);
            let ct1 = header::decode(st.args[0].as_bytes()).unwrap();
            let ct2 = header::decode(st.args[1].as_bytes()).unwrap();
            let ss1 = id.frodo.decapsulate(&ct1).unwrap();
            let ss2 = id.mlkem.decapsulate(&ml_kem::Ciphertext::<MlKem768>::try_from(&ct2[..]).unwrap());
            assert_eq!(hex(derive_kek(&ss1, &ss2[..], &ct1, &ct2).expose()), v.kek);
            assert_eq!(id.unwrap(&[st]).unwrap().expose(), &fk);
        }
    }

    #[test]
    fn fresh_wraps_differ_and_foreign_keys_do_not_match() {
        let a = Identity::generate(&mut crate::rng::os());
        let b = Identity::generate(&mut crate::rng::os());
        let fk = [7u8; 32];
        let s1 = a.recipient().wrap(&fk, &mut crate::rng::os());
        let s2 = a.recipient().wrap(&fk, &mut crate::rng::os());
        assert!(s1.args != s2.args && s1.body != s2.body, "encapsulations must be fresh");
        assert_eq!(b.unwrap(std::slice::from_ref(&s1)).err(), Some(UnwrapError::NotMine));
        let mut bad = s1.clone();
        bad.args.pop();
        assert!(matches!(a.unwrap(&[bad]), Err(UnwrapError::Malformed(_))));
        let mut other = s1.clone();
        other.typ = "x25519".into();
        assert_eq!(a.unwrap(&[other, s1]).unwrap().expose(), &fk);
    }
}
