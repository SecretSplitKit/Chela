//! Constant-time helpers: running time depends on input lengths only, not values; no Spectre mitigations.

/// Constant-time equality of two byte slices. Lengths are not treated as secret; for
/// equal-length inputs running time is `O(a.len())` regardless of where they differ.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    ct_is_zero_u8(diff)
}

/// Return `true` if `x == 0`, without branching on `x`.
#[must_use]
pub fn ct_is_zero_u8(x: u8) -> bool {
    // For non-zero x, `v.wrapping_neg() | v` has its sign bit set; for zero it is 0.
    let v = u32::from(x);
    ((v.wrapping_neg() | v) >> 31) & 1 == 0
}

#[cfg(test)]
mod tests {
    use super::{ct_eq, ct_is_zero_u8};

    #[test]
    fn ct_eq_equal_slices() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"x", b"x"));
        assert!(ct_eq(b"abcdef", b"abcdef"));
        assert!(ct_eq(&[0u8; 32], &[0u8; 32]));
        assert!(ct_eq(&[0xff; 64], &[0xff; 64]));
    }

    #[test]
    fn ct_eq_different_slices() {
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abz"));
        for pos in 0..32 {
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            a[pos] = 1;
            assert!(!ct_eq(&a, &b), "pos {pos}: expected !ct_eq");
            b[pos] = 1;
            assert!(ct_eq(&a, &b), "pos {pos}: expected ct_eq after match");
        }
    }

    #[test]
    fn ct_eq_different_lengths() {
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abc"));
        assert!(!ct_eq(b"", b"x"));
        assert!(!ct_eq(b"x", b""));
    }

    #[test]
    fn ct_is_zero_u8_truth_table() {
        assert!(ct_is_zero_u8(0));
        for v in 1u8..=255 {
            assert!(!ct_is_zero_u8(v), "ct_is_zero_u8({v}) should be false");
        }
    }
}
