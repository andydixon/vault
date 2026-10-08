// SPDX-License-Identifier: GPL-3.0-or-later

//! FrodoKEM-640-SHAKE exactly as CIRCL v1.6.4 implements it
//! (`kem/frodo/frodo640shake`): the round-3 FrodoKEM with a 48-byte key
//! seed, 16-byte encapsulation seed, 16-byte shared secret and 9720-byte
//! ciphertext. The RustCrypto `frodo-kem` crate implements the later ISO
//! variant (salted, 9752-byte ciphertexts, a different seed layout), which
//! cannot open existing vaults, so this module is a line-by-line port of
//! CIRCL's code, checked against vectors from the Go oracle and against the
//! NIST KAT digest CIRCL itself tests.
//!
//! All arithmetic is mod 2^16 with masking to 15 bits where CIRCL masks;
//! loops never branch on secret data, and the decapsulation re-encryption
//! check selects the rejection secret with a constant-time mask.

use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zeroize::Zeroize;

const N: usize = 640;
const NBAR: usize = 8;
const LOG_Q: u32 = 15;
const Q_MASK: u16 = (1 << LOG_Q) - 1;
const SEED_A: usize = 16;
const PK_HASH: usize = 16;
const EXTRACTED_BITS: u32 = 2;
const MESSAGE: usize = 16;
const BP_PACKED: usize = (LOG_Q as usize * N * NBAR) / 8;

pub const SHARED_KEY_SIZE: usize = 16;
pub const KEY_SEED_SIZE: usize = SHARED_KEY_SIZE + SHARED_KEY_SIZE + 16;
pub const ENCAPSULATION_SEED_SIZE: usize = 16;
pub const CIPHERTEXT_SIZE: usize = 9720;
pub const PUBLIC_KEY_SIZE: usize = 9616;
pub const PRIVATE_KEY_SIZE: usize = 19888;

const CDF: [u16; 13] = [
    4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767,
];

/// A packed public key (`seedA || pack(B)`), as CIRCL's `MarshalBinary`.
pub struct PublicKey {
    seed_a: [u8; SEED_A],
    b: Vec<u16>, // N x NBAR
}

/// A private key. Its secret parts are cleared on drop.
pub struct PrivateKey {
    s_reject: [u8; SHARED_KEY_SIZE],
    pk: PublicKey,
    s: Vec<u16>, // transpose(S), NBAR x N
    hpk: [u8; PK_HASH],
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.s_reject.zeroize();
        self.s.zeroize();
    }
}

fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake128::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

fn le_u16s(bytes: &[u8], out: &mut [u16]) {
    for (o, c) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *o = u16::from_le_bytes([c[0], c[1]]);
    }
}

/// Inverse-transform sampling from the FrodoKEM error distribution.
fn sample(v: &mut [u16]) {
    for x in v.iter_mut() {
        let sign = *x & 1;
        let unif = *x >> 1;
        let mut g: u16 = 0;
        for c in &CDF[..CDF.len() - 1] {
            g = g.wrapping_add(c.wrapping_sub(unif) >> 15);
        }
        *x = (sign.wrapping_neg() ^ g).wrapping_add(sign);
    }
}

/// Row i of A is SHAKE128(le16(i) || seedA), as little-endian u16s.
fn expand_a(seed_a: &[u8; SEED_A]) -> Vec<u16> {
    let mut a = vec![0u16; N * N];
    let mut input = [0u8; 2 + SEED_A];
    input[2..].copy_from_slice(seed_a);
    let mut row = [0u8; N * 2];
    for i in 0..N {
        input[0] = i as u8;
        input[1] = (i >> 8) as u8;
        shake(&[&input], &mut row);
        le_u16s(&row, &mut a[i * N..(i + 1) * N]);
    }
    a
}

/// out (N x NBAR) += A*S + E, with S stored transposed (NBAR x N).
fn mul_add_as_plus_e(out: &mut [u16], a: &[u16], s: &[u16], e: &[u16]) {
    for i in 0..N {
        let row = &a[i * N..(i + 1) * N];
        for k in 0..NBAR {
            let sk = &s[k * N..(k + 1) * N];
            let mut sum = e[i * NBAR + k];
            for j in 0..N {
                sum = sum.wrapping_add(row[j].wrapping_mul(sk[j]));
            }
            out[i * NBAR + k] = out[i * NBAR + k].wrapping_add(sum);
        }
    }
}

/// out (NBAR x N) += S*A + E. CIRCL walks A by column; summing row by row
/// gives the same result mod 2^16 with far better locality.
fn mul_add_sa_plus_e(out: &mut [u16], s: &[u16], a: &[u16], e: &[u16]) {
    let mut acc = e[..NBAR * N].to_vec();
    for j in 0..N {
        let row = &a[j * N..(j + 1) * N];
        for k in 0..NBAR {
            let skj = s[k * N + j];
            let dst = &mut acc[k * N..(k + 1) * N];
            for i in 0..N {
                dst[i] = dst[i].wrapping_add(row[i].wrapping_mul(skj));
            }
        }
    }
    for (o, v) in out.iter_mut().zip(&acc) {
        *o = o.wrapping_add(*v);
    }
    acc.zeroize();
}

/// out (NBAR x NBAR) = S*B + E, masked.
fn mul_add_sb_plus_e(out: &mut [u16], s: &[u16], b: &[u16], e: &[u16]) {
    for k in 0..NBAR {
        for i in 0..NBAR {
            let mut v = e[k * NBAR + i];
            for j in 0..N {
                v = v.wrapping_add(s[k * N + j].wrapping_mul(b[j * NBAR + i]));
            }
            out[k * NBAR + i] = v & Q_MASK;
        }
    }
}

/// out (NBAR x NBAR) = B'*S, with S transposed, masked.
fn mul_bs(out: &mut [u16], b: &[u16], s: &[u16]) {
    for i in 0..NBAR {
        for j in 0..NBAR {
            let mut v: u16 = 0;
            for k in 0..N {
                v = v.wrapping_add(b[i * N + k].wrapping_mul(s[j * N + k]));
            }
            out[i * NBAR + j] = v & Q_MASK;
        }
    }
}

fn pack(out: &mut [u8], v: &[u16]) {
    for (o, x) in out.as_chunks_mut::<15>().0.iter_mut().zip(v.as_chunks::<8>().0) {
        let m: [u16; 8] = core::array::from_fn(|i| x[i] & Q_MASK);
        o[0] = (m[0] >> 7) as u8;
        o[1] = (((m[0] & 0x7f) as u8) << 1) | (m[1] >> 14) as u8;
        o[2] = (m[1] >> 6) as u8;
        o[3] = (((m[1] & 0x3f) as u8) << 2) | (m[2] >> 13) as u8;
        o[4] = (m[2] >> 5) as u8;
        o[5] = (((m[2] & 0x1f) as u8) << 3) | (m[3] >> 12) as u8;
        o[6] = (m[3] >> 4) as u8;
        o[7] = (((m[3] & 0x0f) as u8) << 4) | (m[4] >> 11) as u8;
        o[8] = (m[4] >> 3) as u8;
        o[9] = (((m[4] & 0x07) as u8) << 5) | (m[5] >> 10) as u8;
        o[10] = (m[5] >> 2) as u8;
        o[11] = (((m[5] & 0x03) as u8) << 6) | (m[6] >> 9) as u8;
        o[12] = (m[6] >> 1) as u8;
        o[13] = (((m[6] & 0x01) as u8) << 7) | (m[7] >> 8) as u8;
        o[14] = m[7] as u8;
    }
}

fn unpack(out: &mut [u16], b: &[u8]) {
    for (o, i) in out.as_chunks_mut::<8>().0.iter_mut().zip(b.as_chunks::<15>().0) {
        let w = |x: u8| x as u16;
        o[0] = (w(i[0]) << 7) | (w(i[1] & 0xfe) >> 1);
        o[1] = (w(i[1] & 0x01) << 14) | (w(i[2]) << 6) | (w(i[3] & 0xfc) >> 2);
        o[2] = (w(i[3] & 0x03) << 13) | (w(i[4]) << 5) | (w(i[5] & 0xf8) >> 3);
        o[3] = (w(i[5] & 0x07) << 12) | (w(i[6]) << 4) | (w(i[7] & 0xf0) >> 4);
        o[4] = (w(i[7] & 0x0f) << 11) | (w(i[8]) << 3) | (w(i[9] & 0xe0) >> 5);
        o[5] = (w(i[9] & 0x1f) << 10) | (w(i[10]) << 2) | (w(i[11] & 0xc0) >> 6);
        o[6] = (w(i[11] & 0x3f) << 9) | (w(i[12]) << 1) | (w(i[13] & 0x80) >> 7);
        o[7] = (w(i[13] & 0x7f) << 8) | w(i[14]);
    }
}

fn encode_message(out: &mut [u16], msg: &[u8; MESSAGE]) {
    let mask = (1u16 << EXTRACTED_BITS) - 1;
    let mut pos = 0;
    for c in msg.as_chunks::<2>().0 {
        let mut v = u16::from_le_bytes([c[0], c[1]]);
        for _ in 0..(16 / EXTRACTED_BITS) {
            out[pos] = (v & mask) << (LOG_Q - EXTRACTED_BITS);
            pos += 1;
            v >>= EXTRACTED_BITS;
        }
    }
}

fn decode_message(out: &mut [u8; MESSAGE], m: &[u16]) {
    let mask = (1u16 << EXTRACTED_BITS) - 1;
    let mut pos = 0;
    for o in out.iter_mut() {
        for j in 0..(8 / EXTRACTED_BITS) {
            let mut t = (m[pos] & Q_MASK) + (1 << (LOG_Q - EXTRACTED_BITS - 1));
            t >>= LOG_Q - EXTRACTED_BITS;
            t &= mask;
            *o |= (t as u8) << (j * EXTRACTED_BITS);
            pos += 1;
        }
    }
}

/// 0 if equal, 1 otherwise, without branching on the contents.
fn ct_differs(a: &[u16], b: &[u16]) -> u8 {
    let mut v: u16 = 0;
    for (x, y) in a.iter().zip(b) {
        v |= x ^ y;
    }
    ((v | v.wrapping_neg()) >> 15) as u8
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; PUBLIC_KEY_SIZE];
        out[..SEED_A].copy_from_slice(&self.seed_a);
        pack(&mut out[SEED_A..], &self.b);
        out
    }

    /// Any 9616 bytes form a key, as in CIRCL; only the length is checked.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != PUBLIC_KEY_SIZE {
            return None;
        }
        let mut seed_a = [0u8; SEED_A];
        seed_a.copy_from_slice(&buf[..SEED_A]);
        let mut b = vec![0u16; N * NBAR];
        unpack(&mut b, &buf[SEED_A..]);
        Some(PublicKey { seed_a, b })
    }

    fn hash(&self) -> [u8; PK_HASH] {
        let mut h = [0u8; PK_HASH];
        shake(&[&self.to_bytes()], &mut h);
        h
    }

    /// Encapsulates with the 16-byte message `mu` (CIRCL's
    /// `EncapsulateTo` seed), returning the ciphertext and shared secret.
    /// Callers must pass fresh randomness; reusing `mu` repeats the secret.
    pub fn encapsulate(&self, mu: &[u8; ENCAPSULATION_SEED_SIZE]) -> (Vec<u8>, [u8; SHARED_KEY_SIZE]) {
        let hpk = self.hash();
        let mut g2 = [0u8; 2 * SHARED_KEY_SIZE];
        shake(&[&hpk, mu], &mut g2);
        let (sp, ep, epp, mut noise) = noise(&g2[..SHARED_KEY_SIZE]);
        let a = expand_a(&self.seed_a);
        let mut bp = vec![0u16; NBAR * N];
        mul_add_sa_plus_e(&mut bp, &noise[sp.clone()], &a, &noise[ep]);
        let mut v = [0u16; NBAR * NBAR];
        mul_add_sb_plus_e(&mut v, &noise[sp], &self.b, &noise[epp]);
        let mut c = [0u16; NBAR * NBAR];
        encode_message(&mut c, mu);
        for (c, v) in c.iter_mut().zip(&v) {
            *c = c.wrapping_add(*v) & Q_MASK;
        }
        let mut ct = vec![0u8; CIPHERTEXT_SIZE];
        pack(&mut ct[..BP_PACKED], &bp);
        pack(&mut ct[BP_PACKED..], &c);
        let mut ss = [0u8; SHARED_KEY_SIZE];
        shake(&[&ct, &g2[SHARED_KEY_SIZE..]], &mut ss);
        noise.zeroize();
        g2.zeroize();
        v.zeroize();
        (ct, ss)
    }
}

type Span = core::ops::Range<usize>;

/// SHAKE128(0x96 || seedSE) expanded and sampled into S', E', E''.
fn noise(seed_se: &[u8]) -> (Span, Span, Span, Vec<u16>) {
    let total = 2 * N * NBAR + NBAR * NBAR;
    let mut bytes = vec![0u8; 2 * total];
    shake(&[&[0x96], seed_se], &mut bytes);
    let mut v = vec![0u16; total];
    le_u16s(&bytes, &mut v);
    bytes.zeroize();
    sample(&mut v);
    (0..N * NBAR, N * NBAR..2 * N * NBAR, 2 * N * NBAR..total, v)
}

impl PrivateKey {
    /// CIRCL's `newKeyFromSeed`: seed is s || seedSE || z.
    pub fn derive(seed: &[u8; KEY_SEED_SIZE]) -> Self {
        let mut seed_a = [0u8; SEED_A];
        shake(&[&seed[2 * SHARED_KEY_SIZE..]], &mut seed_a);
        let mut bytes = vec![0u8; 2 * 2 * N * NBAR];
        shake(&[&[0x5f], &seed[SHARED_KEY_SIZE..2 * SHARED_KEY_SIZE]], &mut bytes);
        let mut s = vec![0u16; N * NBAR];
        let mut e = vec![0u16; N * NBAR];
        le_u16s(&bytes[..2 * N * NBAR], &mut s);
        le_u16s(&bytes[2 * N * NBAR..], &mut e);
        bytes.zeroize();
        sample(&mut s);
        sample(&mut e);
        let a = expand_a(&seed_a);
        let mut b = vec![0u16; N * NBAR];
        mul_add_as_plus_e(&mut b, &a, &s, &e);
        e.zeroize();
        let pk = PublicKey { seed_a, b };
        let hpk = pk.hash();
        let mut s_reject = [0u8; SHARED_KEY_SIZE];
        s_reject.copy_from_slice(&seed[..SHARED_KEY_SIZE]);
        PrivateKey { s_reject, pk, s, hpk }
    }

    pub fn public(&self) -> &PublicKey {
        &self.pk
    }

    /// CIRCL's packed form: s || pk || S (little-endian) || H(pk).
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut out = zeroize::Zeroizing::new(Vec::with_capacity(PRIVATE_KEY_SIZE));
        out.extend_from_slice(&self.s_reject);
        out.extend_from_slice(&self.pk.to_bytes());
        for x in &self.s {
            out.extend_from_slice(&x.to_le_bytes());
        }
        out.extend_from_slice(&self.hpk);
        out
    }

    /// Decapsulates with implicit rejection: a ciphertext that does not
    /// re-encrypt identically yields SHAKE(ct || s) instead of an error.
    pub fn decapsulate(&self, ct: &[u8]) -> Option<[u8; SHARED_KEY_SIZE]> {
        if ct.len() != CIPHERTEXT_SIZE {
            return None;
        }
        let mut bp = vec![0u16; NBAR * N];
        let mut c = [0u16; NBAR * NBAR];
        unpack(&mut bp, &ct[..BP_PACKED]);
        unpack(&mut c, &ct[BP_PACKED..]);
        let mut w = [0u16; NBAR * NBAR];
        mul_bs(&mut w, &bp, &self.s);
        for (w, c) in w.iter_mut().zip(&c) {
            *w = c.wrapping_sub(*w) & Q_MASK;
        }
        let mut mu = [0u8; MESSAGE];
        decode_message(&mut mu, &w);

        let mut g2 = [0u8; 2 * SHARED_KEY_SIZE];
        shake(&[&self.hpk, &mu], &mut g2);
        let (sp, ep, epp, mut noise) = noise(&g2[..SHARED_KEY_SIZE]);
        let a = expand_a(&self.pk.seed_a);
        let mut bbp = vec![0u16; NBAR * N];
        mul_add_sa_plus_e(&mut bbp, &noise[sp.clone()], &a, &noise[ep]);
        for x in bbp.iter_mut() {
            *x &= Q_MASK;
        }
        mul_add_sb_plus_e(&mut w, &noise[sp], &self.pk.b, &noise[epp]);
        let mut cc = [0u16; NBAR * NBAR];
        encode_message(&mut cc, &mu);
        for (cc, w) in cc.iter_mut().zip(&w) {
            *cc = cc.wrapping_add(*w) & Q_MASK;
        }
        let differs = ct_differs(&bp, &bbp) | ct_differs(&c, &cc);
        let mask = differs.wrapping_neg(); // 0xff to reject, 0 to accept
        let mut k = [0u8; SHARED_KEY_SIZE];
        for (i, k) in k.iter_mut().enumerate() {
            *k = (g2[SHARED_KEY_SIZE + i] & !mask) | (self.s_reject[i] & mask);
        }
        let mut ss = [0u8; SHARED_KEY_SIZE];
        shake(&[ct, &k], &mut ss);
        for z in [&mut mu[..], &mut g2[..], &mut k[..]] {
            z.zeroize();
        }
        noise.zeroize();
        w.zeroize();
        cc.zeroize();
        bbp.zeroize();
        Some(ss)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    use sha2::Digest;

    /// NIST's AES-256 CTR_DRBG from the KAT generator's randombytes.c.
    struct Drbg {
        key: [u8; 32],
        v: [u8; 16],
    }

    impl Drbg {
        fn new(entropy: &[u8; 48]) -> Self {
            let mut d = Drbg { key: [0; 32], v: [0; 16] };
            d.update(Some(entropy));
            d
        }

        fn block(&mut self) -> [u8; 16] {
            for b in self.v.iter_mut().rev() {
                *b = b.wrapping_add(1);
                if *b != 0 {
                    break;
                }
            }
            let c = aes::Aes256::new(&self.key.into());
            let mut blk = self.v.into();
            c.encrypt_block(&mut blk);
            blk.into()
        }

        fn update(&mut self, data: Option<&[u8; 48]>) {
            let mut t = [0u8; 48];
            for i in 0..3 {
                t[16 * i..16 * i + 16].copy_from_slice(&self.block());
            }
            if let Some(d) = data {
                for (t, d) in t.iter_mut().zip(d) {
                    *t ^= d;
                }
            }
            self.key.copy_from_slice(&t[..32]);
            self.v.copy_from_slice(&t[32..]);
        }

        fn fill(&mut self, out: &mut [u8]) {
            for c in out.chunks_mut(16) {
                let b = self.block();
                c.copy_from_slice(&b[..c.len()]);
            }
            self.update(None);
        }
    }

    fn upper(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02X}")).collect()
    }

    /// CIRCL's TestPQCgenKATKem: the SHA-256 of the KAT response file it
    /// regenerates, which matches the FrodoKEM reference implementation's
    /// PQCkemKAT_19888_shake.rsp.
    #[test]
    fn nist_kat_digest() {
        let mut seed = [0u8; 48];
        for (i, s) in seed.iter_mut().enumerate() {
            *s = i as u8;
        }
        let mut g = Drbg::new(&seed);
        let mut f = sha2::Sha256::new();
        Digest::update(&mut f, b"# FrodoKEM-640-SHAKE\n\n");
        for i in 0..100 {
            g.fill(&mut seed);
            Digest::update(&mut f, format!("count = {i}\nseed = {}\n", upper(&seed)).as_bytes());
            let mut g2 = Drbg::new(&seed);
            let mut kseed = [0u8; KEY_SEED_SIZE];
            g2.fill(&mut kseed);
            let sk = PrivateKey::derive(&kseed);
            let pk = sk.public().to_bytes();
            let mut eseed = [0u8; ENCAPSULATION_SEED_SIZE];
            g2.fill(&mut eseed);
            let (ct, ss) = PublicKey::from_bytes(&pk).unwrap().encapsulate(&eseed);
            assert_eq!(sk.decapsulate(&ct).unwrap(), ss);
            Digest::update(
                &mut f,
                format!(
                    "pk = {}\nsk = {}\nct = {}\nss = {}\n\n",
                    upper(&pk),
                    upper(&sk.to_bytes()),
                    upper(&ct),
                    upper(&ss)
                )
                .as_bytes(),
            );
        }
        let digest: String = f.finalize().iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(digest, "604a10cfc871dfaed9cb5b057c644ab03b16852cea7f39bc7f9831513b5b1cfa");
    }
}
