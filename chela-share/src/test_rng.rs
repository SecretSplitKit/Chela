//! Deterministic RNG shared by this crate's tests.

use chela_sss::{RandomSource, SssError};

/// xorshift64 PRNG so tests run on fixed share data instead of OS-random words.
///
/// Random words make data-dependent assertions flaky: a Y word can collide with a
/// wordlist token, or a single-bit corruption can slip past the 11-bit per-share CRC
/// at its alternate candidate body length (~1/2048 of the time). Seed once, get an
/// unlimited reproducible byte stream.
pub(crate) struct SeededRng(pub u64);

impl RandomSource for SeededRng {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), SssError> {
        for slot in buf.iter_mut() {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            *slot = (x >> 56) as u8;
        }
        Ok(())
    }
}
