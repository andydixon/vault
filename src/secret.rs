// SPDX-License-Identifier: GPL-3.0-or-later

//! Owned secret buffers.
//!
//! These types are deliberately neither `Clone`, `Copy`, `Debug` nor
//! serialisable, so a secret cannot be duplicated or printed by accident.
//! Each is heap-allocated once at its final size and cleared with `zeroize`
//! when dropped, including during unwinding. Clearing shortens the lifetime
//! of the bytes these types own; it cannot reach copies the compiler made in
//! registers or on the stack, copies held inside third-party crates' key
//! objects, or memory already swapped out, and an abort or kill skips it.

use zeroize::Zeroize;

/// A fixed-size secret, boxed so moving it never copies the bytes.
pub struct SecretArray<const N: usize>(Box<[u8; N]>);

impl<const N: usize> SecretArray<N> {
    pub fn zero() -> Self {
        SecretArray(Box::new([0u8; N]))
    }

    pub fn from_slice(b: &[u8]) -> Option<Self> {
        let mut s = Self::zero();
        if b.len() != N {
            return None;
        }
        s.0.copy_from_slice(b);
        Some(s)
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Drop for SecretArray<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A variable-length secret such as a passphrase or decrypted plaintext.
/// The capacity is fixed at creation; operations that could reallocate (and
/// leave an uncleared copy behind) are not offered.
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    pub fn with_capacity(n: usize) -> Self {
        SecretVec(Vec::with_capacity(n))
    }

    /// Takes ownership of `v`, which from now on is cleared on drop.
    pub fn from_vec(v: Vec<u8>) -> Self {
        SecretVec(v)
    }

    pub fn zeroed(n: usize) -> Self {
        SecretVec(vec![0u8; n])
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Appends without reallocating; panics if `b` does not fit.
    pub fn extend_within_capacity(&mut self, b: &[u8]) {
        assert!(self.0.len() + b.len() <= self.0.capacity(), "secret buffer would reallocate");
        self.0.extend_from_slice(b);
    }

    /// Resizes within the existing capacity, zero-filling any growth;
    /// panics rather than reallocate.
    pub fn resize_within_capacity(&mut self, n: usize) {
        assert!(n <= self.0.capacity(), "secret buffer would reallocate");
        if n < self.0.len() {
            self.0[n..].zeroize();
        }
        self.0.resize(n, 0);
    }

    /// Clears the contents for reuse, keeping the allocation. Bytes past
    /// the length are always zero already (shrinking clears them), so only
    /// the live part needs overwriting.
    pub fn clear(&mut self) {
        self.0.as_mut_slice().zeroize();
        self.0.clear();
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        // Zeroize the whole capacity, not just the live length.
        self.0.zeroize();
    }
}

impl PartialEq<[u8]> for SecretVec {
    fn eq(&self, other: &[u8]) -> bool {
        use subtle_eq::ct_eq;
        ct_eq(&self.0, other)
    }
}

pub(crate) mod subtle_eq {
    /// Constant-time equality for equal-length inputs; lengths are public.
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut d = 0u8;
        for (x, y) in a.iter().zip(b) {
            d |= x ^ y;
        }
        core::hint::black_box(d) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_vec_never_reallocates() {
        let mut s = SecretVec::with_capacity(4);
        s.extend_within_capacity(b"ab");
        s.resize_within_capacity(4);
        assert_eq!(s.expose(), b"ab\0\0");
        assert!(std::panic::catch_unwind(move || s.extend_within_capacity(b"x")).is_err());
    }

    #[test]
    fn secret_array_length_checked() {
        assert!(SecretArray::<4>::from_slice(b"abc").is_none());
        assert_eq!(SecretArray::<3>::from_slice(b"abc").unwrap().expose(), b"abc");
    }
}
