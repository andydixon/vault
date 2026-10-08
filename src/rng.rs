// SPDX-License-Identifier: GPL-3.0-or-later

//! Randomness.
//!
//! Production code only ever uses the operating system's CSPRNG. Unit tests
//! can substitute a seeded generator so that sequential and parallel paths
//! can be compared byte for byte; that variant exists only under
//! `cfg(test)` and cannot be selected by a user or a build of the binary.

/// Where a computation draws its randomness from. Each independent unit of
/// work asks for its own [`Rng`] by label, so seeded test runs stay
/// deterministic however work is scheduled across threads.
#[derive(Clone)]
pub enum Entropy {
    Os,
    #[cfg(test)]
    Seeded([u8; 32]),
}

pub enum Rng {
    Os,
    #[cfg(test)]
    Seeded(Box<dyn sha3::digest::XofReader + Send>),
}

impl Entropy {
    pub fn rng(&self, _label: &[u8]) -> Rng {
        match self {
            Entropy::Os => Rng::Os,
            #[cfg(test)]
            Entropy::Seeded(seed) => {
                use sha3::digest::{ExtendableOutput, Update};
                let mut h = sha3::Shake256::default();
                h.update(b"vault test rng");
                h.update(seed);
                h.update(&(_label.len() as u64).to_be_bytes());
                h.update(_label);
                Rng::Seeded(Box::new(h.finalize_xof()))
            }
        }
    }
}

impl Rng {
    pub fn fill(&mut self, out: &mut [u8]) {
        match self {
            // A failing system CSPRNG is not something to continue past,
            // exactly as Go's crypto/rand treats it.
            Rng::Os => getrandom::fill(out).expect("vault: the operating system's random number generator failed"),
            #[cfg(test)]
            Rng::Seeded(r) => r.read(out),
        }
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        self.fill(&mut b);
        b
    }

    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.array())
    }

    /// A uniform float in [0, 1).
    pub fn f64(&mut self) -> f64 {
        (self.u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A uniform integer in [0, n), n > 0, without modulo bias.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.u64();
            if v < zone {
                return v % n;
            }
        }
    }
}

/// Shorthand for operating-system randomness.
pub fn os() -> Rng {
    Rng::Os
}
