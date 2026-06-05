//! Shamir's Secret Sharing over GF(2^8): byte-wise polynomial splitting and recovery
//! by Lagrange interpolation at x=0, using caller-allocated buffers (`#![no_std]`).

#![no_std]
#![deny(unsafe_code)]

use chela_field::{Field, Gf256};

/// Maximum threshold / total share count. GF(2^8) has 255 non-zero x-coordinates
/// (`1..=255`); x=0 is the secret.
pub const MAX_THRESHOLD: u8 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SssError {
    InvalidThreshold,
    InvalidShareCount,
    /// Duplicate x-coordinate among shares, or x = 0 (which is the secret itself).
    DuplicateXCoordinate,
    InsufficientShares,
    InconsistentLength,
    RngFailed,
}

/// Source of cryptographically-secure random bytes used by [`split`].
pub trait RandomSource {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), SssError>;
}

/// Production [`RandomSource`] backed by the OS RNG in `chela_primitives::rng`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRng;

impl RandomSource for OsRng {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), SssError> {
        chela_primitives::rng::fill_bytes(buf).map_err(|_| SssError::RngFailed)
    }
}

/// Split `secret` into `total` shares with reconstruction threshold `threshold`.
///
/// `out_x` (len `total`) is an input: the caller's chosen x-coordinates, which must be
/// non-zero and distinct (x = 0 is the secret; Lagrange needs distinct points).
/// `out_shares` (outer len `total`, inner len `secret.len()`) receives the share byte
/// strings.
pub fn split(
    secret: &[u8],
    threshold: u8,
    total: u8,
    rng: &mut dyn RandomSource,
    out_x: &mut [u8],
    out_shares: &mut [&mut [u8]],
) -> Result<(), SssError> {
    if threshold == 0 || threshold > total {
        return Err(SssError::InvalidThreshold);
    }
    if total == 0 {
        return Err(SssError::InvalidShareCount);
    }
    if out_x.len() != usize::from(total) || out_shares.len() != usize::from(total) {
        return Err(SssError::InconsistentLength);
    }
    for share in out_shares.iter() {
        if share.len() != secret.len() {
            return Err(SssError::InconsistentLength);
        }
    }

    // Caller supplies the x-coordinates in `out_x`; they MUST be non-zero and distinct
    // (x = 0 is the secret; Lagrange needs distinct points).
    for (i, &xi) in out_x.iter().enumerate() {
        if xi == 0 || out_x[i + 1..].contains(&xi) {
            return Err(SssError::DuplicateXCoordinate);
        }
    }

    let mut coeffs = [Gf256::ZERO; MAX_THRESHOLD as usize];
    let mut rand_buf = [0u8; MAX_THRESHOLD as usize];

    let m = usize::from(threshold);

    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        coeffs[0] = Gf256(secret_byte);

        let random_slice = &mut rand_buf[..m - 1];
        if let Err(e) = rng.fill_random(random_slice) {
            // `coeffs[0]` already holds this secret byte; wipe scratch on the error path.
            chela_primitives::zeroize::volatile_set(&mut rand_buf);
            wipe_coeffs(&mut coeffs);
            return Err(e);
        }
        for k in 1..m {
            coeffs[k] = Gf256(rand_buf[k - 1]);
        }

        for (share_idx, &x) in out_x.iter().enumerate() {
            let v = Gf256::evaluate_polynomial(&coeffs[..m], Gf256(x));
            out_shares[share_idx][byte_idx] = v.as_u8();
        }
    }

    // Polynomial coefficients and random scratch reveal the sharing polynomial; wipe.
    chela_primitives::zeroize::volatile_set(&mut rand_buf);
    wipe_coeffs(&mut coeffs);

    Ok(())
}

/// Volatile-wipe the polynomial coefficient buffer. Reinterprets `&mut [Gf256]` as
/// `&mut [u8]` — sound because `Gf256` is `#[repr(transparent)]` over `u8`. A plain
/// `coeffs.fill(Gf256::ZERO)` is dead-store-eligible because `coeffs` isn't read
/// afterwards; the volatile write + compiler fence inside `volatile_set` prevents that.
#[allow(unsafe_code)]
fn wipe_coeffs(coeffs: &mut [Gf256]) {
    // SAFETY: `Gf256` is `#[repr(transparent)]` over `u8`, so a slice of `N` `Gf256`s
    // has identical layout to a slice of `N` `u8`s (no padding, any byte pattern valid
    // for both). The `&mut` borrow guarantees unique, valid-for-writes access for
    // exactly `coeffs.len()` bytes.
    let bytes: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(coeffs.as_mut_ptr().cast::<u8>(), coeffs.len()) };
    chela_primitives::zeroize::volatile_set(bytes);
}

/// Reconstruct the secret from `share_values` at x-coordinates `xs` into `out`. All
/// `share_values[i]` and `out` must have the same length. The caller must supply at least
/// the threshold number of shares; fewer returns noise (not an error) since the function
/// cannot know the threshold from share data.
pub fn combine(xs: &[u8], share_values: &[&[u8]], out: &mut [u8]) -> Result<(), SssError> {
    if xs.is_empty() || xs.len() != share_values.len() {
        return Err(SssError::InsufficientShares);
    }
    if xs.len() > MAX_THRESHOLD as usize {
        return Err(SssError::InvalidShareCount);
    }
    for share in share_values {
        if share.len() != out.len() {
            return Err(SssError::InconsistentLength);
        }
    }
    for (i, &xi) in xs.iter().enumerate() {
        if xs[i + 1..].contains(&xi) {
            return Err(SssError::DuplicateXCoordinate);
        }
    }
    if xs.contains(&0) {
        return Err(SssError::DuplicateXCoordinate);
    }

    // L_i(0) = Π_{j != i} x_j / (x_i XOR x_j)  (in GF(2^8), negation is identity).
    let mut lagrange = [Gf256::ZERO; MAX_THRESHOLD as usize];
    #[allow(clippy::needless_range_loop)]
    for i in 0..xs.len() {
        let xi = Gf256(xs[i]);
        let mut numerator = Gf256::ONE;
        let mut denominator = Gf256::ONE;
        for j in 0..xs.len() {
            if i == j {
                continue;
            }
            let xj = Gf256(xs[j]);
            numerator = numerator.mul(xj);
            denominator = denominator.mul(xi.sub(xj));
        }
        lagrange[i] = numerator.mul(denominator.inv());
    }

    for (byte_idx, out_byte) in out.iter_mut().enumerate() {
        let mut acc = Gf256::ZERO;
        for (i, share) in share_values.iter().enumerate() {
            acc = acc.add(Gf256(share[byte_idx]).mul(lagrange[i]));
        }
        *out_byte = acc.as_u8();
    }

    lagrange.fill(Gf256::ZERO);

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::{combine, split, OsRng, RandomSource, SssError, MAX_THRESHOLD};
    use alloc::vec;
    use alloc::vec::Vec;

    struct DeterministicRng<'a> {
        source: &'a [u8],
        pos: usize,
    }

    impl<'a> DeterministicRng<'a> {
        fn new(source: &'a [u8]) -> Self {
            Self { source, pos: 0 }
        }
    }

    impl RandomSource for DeterministicRng<'_> {
        fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), SssError> {
            if self.pos + buf.len() > self.source.len() {
                return Err(SssError::RngFailed);
            }
            buf.copy_from_slice(&self.source[self.pos..self.pos + buf.len()]);
            self.pos += buf.len();
            Ok(())
        }
    }

    fn do_split(
        secret: &[u8],
        threshold: u8,
        total: u8,
        rng: &mut dyn RandomSource,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), SssError> {
        let mut xs: Vec<u8> = (1..=total).collect();
        let mut shares: Vec<Vec<u8>> = vec![vec![0u8; secret.len()]; total as usize];
        {
            let mut share_refs: Vec<&mut [u8]> = shares.iter_mut().map(Vec::as_mut_slice).collect();
            split(secret, threshold, total, rng, &mut xs, &mut share_refs)?;
        }
        Ok((xs, shares))
    }

    fn do_combine(xs: &[u8], shares: &[Vec<u8>], secret_len: usize) -> Result<Vec<u8>, SssError> {
        let share_refs: Vec<&[u8]> = shares.iter().map(Vec::as_slice).collect();
        let mut out = vec![0u8; secret_len];
        combine(xs, &share_refs, &mut out)?;
        Ok(out)
    }

    // Round-trip: every M-subset of N shares must reconstruct, for all 1<=M<=N<=6.

    #[test]
    fn round_trip_for_every_subset_of_every_m_n_up_to_6() {
        let secret = b"The quick brown fox jumps over the lazy dog.";
        let rand_pool = vec![0x5au8; secret.len() * (MAX_THRESHOLD as usize)];

        for n in 1u8..=6 {
            for m in 1u8..=n {
                let mut rng = DeterministicRng::new(&rand_pool);
                let (xs, shares) = do_split(secret, m, n, &mut rng).unwrap();

                let n_usize = n as usize;
                let m_usize = m as usize;
                for mask in 0u32..(1u32 << n_usize) {
                    if mask.count_ones() as usize != m_usize {
                        continue;
                    }
                    let mut chosen_xs = Vec::with_capacity(m_usize);
                    let mut chosen_shares: Vec<Vec<u8>> = Vec::with_capacity(m_usize);
                    for i in 0..n_usize {
                        if mask & (1 << i) != 0 {
                            chosen_xs.push(xs[i]);
                            chosen_shares.push(shares[i].clone());
                        }
                    }
                    let recovered = do_combine(&chosen_xs, &chosen_shares, secret.len()).unwrap();
                    assert_eq!(
                        recovered.as_slice(),
                        secret,
                        "M={m}, N={n}, mask={mask:#b}: round-trip failed",
                    );
                }
            }
        }
    }

    #[test]
    fn round_trip_with_os_rng_3_of_5() {
        let secret = b"another test secret with \x00 byte and high \xffs";
        let (xs, shares) = do_split(secret, 3, 5, &mut OsRng).unwrap();

        let recovered = do_combine(&xs[..3], &shares[..3], secret.len()).unwrap();
        assert_eq!(recovered.as_slice(), secret);

        let chosen_xs = vec![xs[0], xs[2], xs[4]];
        let chosen_shares = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = do_combine(&chosen_xs, &chosen_shares, secret.len()).unwrap();
        assert_eq!(recovered.as_slice(), secret);
    }

    // Sub-threshold: M-1 shares must not recover (information-theoretic security).

    #[test]
    fn sub_threshold_combine_does_not_recover_secret() {
        let secret = b"super secret 256-bit-equivalent payload bytes!!";
        // The rand pattern must NOT produce identical bytes for consecutive coefficients
        // of the same polynomial; otherwise `c1*x + c2*x` cancels at x=1 and a single
        // share equals the secret. A fixed-value test RNG can hit this; OS-RNG won't.
        let rand_pool: Vec<u8> = (0..secret.len() * 2)
            .map(|i| {
                u8::try_from(i % 256)
                    .unwrap()
                    .wrapping_mul(31)
                    .wrapping_add(7)
            })
            .collect();
        let mut rng = DeterministicRng::new(&rand_pool);
        let (xs, shares) = do_split(secret, 3, 5, &mut rng).unwrap();

        let recovered = do_combine(&xs[..1], &shares[..1], secret.len()).unwrap();
        assert_ne!(
            recovered.as_slice(),
            secret,
            "1 share of 3-of-5 should not recover"
        );

        let recovered = do_combine(&xs[..2], &shares[..2], secret.len()).unwrap();
        assert_ne!(
            recovered.as_slice(),
            secret,
            "2 shares of 3-of-5 should not recover"
        );
    }

    #[test]
    fn split_rejects_zero_threshold() {
        let mut rng = DeterministicRng::new(&[0; 64]);
        let mut xs = [0u8; 3];
        let mut data = [[0u8; 4]; 3];
        let mut refs: Vec<&mut [u8]> = data.iter_mut().map(<[u8; 4]>::as_mut_slice).collect();
        let err = split(b"data", 0, 3, &mut rng, &mut xs, &mut refs).unwrap_err();
        assert_eq!(err, SssError::InvalidThreshold);
    }

    #[test]
    fn split_rejects_threshold_greater_than_total() {
        let mut rng = DeterministicRng::new(&[0; 64]);
        let mut xs = [0u8; 2];
        let mut data = [[0u8; 4]; 2];
        let mut refs: Vec<&mut [u8]> = data.iter_mut().map(<[u8; 4]>::as_mut_slice).collect();
        let err = split(b"data", 5, 2, &mut rng, &mut xs, &mut refs).unwrap_err();
        assert_eq!(err, SssError::InvalidThreshold);
    }

    #[test]
    fn split_uses_caller_supplied_x() {
        let mut rng = DeterministicRng::new(&[0x5a; 64]);
        let mut xs = [7u8, 3u8, 200u8]; // caller-chosen, distinct, non-sequential
        let mut data = [[0u8; 4]; 3];
        let mut refs: Vec<&mut [u8]> = data.iter_mut().map(<[u8; 4]>::as_mut_slice).collect();
        split(b"data", 2, 3, &mut rng, &mut xs, &mut refs).unwrap();
        assert_eq!(
            xs,
            [7, 3, 200],
            "split must not overwrite caller x-coordinates"
        );

        let recovered =
            do_combine(&[xs[0], xs[1]], &[data[0].to_vec(), data[1].to_vec()], 4).unwrap();
        assert_eq!(recovered.as_slice(), b"data");
    }

    #[test]
    fn split_rejects_zero_or_duplicate_caller_x() {
        let mut rng = DeterministicRng::new(&[0x5a; 64]);
        let mut data = [[0u8; 4]; 2];
        {
            let mut xs = [0u8, 1u8];
            let mut refs: Vec<&mut [u8]> = data.iter_mut().map(<[u8; 4]>::as_mut_slice).collect();
            assert_eq!(
                split(b"data", 2, 2, &mut rng, &mut xs, &mut refs).unwrap_err(),
                SssError::DuplicateXCoordinate
            );
        }
        {
            let mut xs = [5u8, 5u8];
            let mut refs: Vec<&mut [u8]> = data.iter_mut().map(<[u8; 4]>::as_mut_slice).collect();
            assert_eq!(
                split(b"data", 2, 2, &mut rng, &mut xs, &mut refs).unwrap_err(),
                SssError::DuplicateXCoordinate
            );
        }
    }

    #[test]
    fn combine_rejects_duplicate_x() {
        let bytes = [&[0u8; 4][..], &[0u8; 4][..]];
        let mut out = [0u8; 4];
        let err = combine(&[3, 3], &bytes, &mut out).unwrap_err();
        assert_eq!(err, SssError::DuplicateXCoordinate);
    }

    #[test]
    fn combine_rejects_zero_x() {
        let bytes = [&[0u8; 4][..], &[0u8; 4][..]];
        let mut out = [0u8; 4];
        let err = combine(&[0, 1], &bytes, &mut out).unwrap_err();
        assert_eq!(err, SssError::DuplicateXCoordinate);
    }

    #[test]
    fn combine_rejects_inconsistent_share_lengths() {
        let bytes = [&[0u8; 4][..], &[0u8; 5][..]];
        let mut out = [0u8; 4];
        let err = combine(&[1, 2], &bytes, &mut out).unwrap_err();
        assert_eq!(err, SssError::InconsistentLength);
    }

    #[test]
    fn combine_rejects_empty_share_set() {
        let mut out = [0u8; 4];
        let err = combine(&[], &[], &mut out).unwrap_err();
        assert_eq!(err, SssError::InsufficientShares);
    }
}
