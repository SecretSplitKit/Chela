//! GF(2^8) over the AES/Rijndael polynomial `x^8 + x^4 + x^3 + x + 1` (`0x11b`) per
//! FIPS 197 § 4.

use crate::Field;

/// Element of GF(2^8) over the Rijndael polynomial `0x11b`, represented as a `u8`.
/// `repr(transparent)` so `&mut [Gf256]` can be safely reinterpreted as `&mut [u8]`
/// for purposes like volatile zeroization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct Gf256(pub u8);

impl Gf256 {
    pub const fn new(byte: u8) -> Self {
        Self(byte)
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for Gf256 {
    fn from(byte: u8) -> Self {
        Self(byte)
    }
}

impl From<Gf256> for u8 {
    fn from(f: Gf256) -> u8 {
        f.0
    }
}

impl Field for Gf256 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }

    fn sub(self, rhs: Self) -> Self {
        // Characteristic 2: subtraction equals addition.
        Self(self.0 ^ rhs.0)
    }

    fn mul(self, rhs: Self) -> Self {
        Self(mul_ct(self.0, rhs.0))
    }

    fn inv(self) -> Self {
        Self(inv_ct(self.0))
    }
}

/// Constant-time GF(2^8) multiplication modulo `0x11b`. Eight-round mask-driven
/// shift-and-XOR with conditional reduction.
fn mul_ct(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a = a;
    let mut b = b;
    let mut round = 0;
    while round < 8 {
        let add_mask = (b & 1).wrapping_neg();
        result ^= a & add_mask;

        let high = (a >> 7) & 1;
        let reduce_mask = high.wrapping_neg();
        a = (a << 1) ^ (reduce_mask & 0x1b);

        b >>= 1;
        round += 1;
    }
    result
}

/// Constant-time GF(2^8) inverse via `x^254 = x^-1` (multiplicative group has order 255).
/// Computed as `x^2 · x^4 · x^8 · x^16 · x^32 · x^64 · x^128`; for `x = 0` every
/// intermediate product is 0, so `inv(0) = 0` is branch-free.
fn inv_ct(x: u8) -> u8 {
    let x2 = mul_ct(x, x);
    let x4 = mul_ct(x2, x2);
    let x8 = mul_ct(x4, x4);
    let x16 = mul_ct(x8, x8);
    let x32 = mul_ct(x16, x16);
    let x64 = mul_ct(x32, x32);
    let x128 = mul_ct(x64, x64);

    let p_low = mul_ct(mul_ct(x2, x4), x8);
    let p_high = mul_ct(mul_ct(x16, x32), mul_ct(x64, x128));
    mul_ct(p_low, p_high)
}

#[cfg(test)]
mod tests {
    use super::Gf256;
    use crate::Field;

    /// FIPS 197 § 4.1: 0x57 · 0x83 = 0xc1.
    #[test]
    fn aes_spec_example_57_times_83() {
        let a = Gf256(0x57);
        let b = Gf256(0x83);
        assert_eq!(a.mul(b), Gf256(0xc1));
        assert_eq!(b.mul(a), Gf256(0xc1));
    }

    #[test]
    fn additive_identity() {
        for v in 0..=255u8 {
            let x = Gf256(v);
            assert_eq!(x.add(Gf256::ZERO), x);
            assert_eq!(Gf256::ZERO.add(x), x);
        }
    }

    #[test]
    fn multiplicative_identity() {
        for v in 0..=255u8 {
            let x = Gf256(v);
            assert_eq!(x.mul(Gf256::ONE), x);
            assert_eq!(Gf256::ONE.mul(x), x);
        }
    }

    #[test]
    fn zero_is_absorbing_for_mul() {
        for v in 0..=255u8 {
            assert_eq!(Gf256(v).mul(Gf256::ZERO), Gf256::ZERO);
            assert_eq!(Gf256::ZERO.mul(Gf256(v)), Gf256::ZERO);
        }
    }

    #[test]
    fn add_is_self_inverse_in_characteristic_two() {
        for v in 0..=255u8 {
            let x = Gf256(v);
            assert_eq!(x.add(x), Gf256::ZERO);
            assert_eq!(x.sub(x), Gf256::ZERO);
        }
    }

    #[test]
    fn multiplication_is_commutative_for_sampled_pairs() {
        for &a in &[0u8, 1, 2, 0x57, 0x83, 0xaa, 0x1b, 0xff] {
            for &b in &[0u8, 1, 2, 0x57, 0x83, 0xaa, 0x1b, 0xff] {
                let lhs = Gf256(a).mul(Gf256(b));
                let rhs = Gf256(b).mul(Gf256(a));
                assert_eq!(lhs, rhs, "mul not commutative: {a:#x} * {b:#x}");
            }
        }
    }

    #[test]
    fn multiplication_distributes_over_addition() {
        for &a in &[1u8, 2, 0x57, 0xaa, 0xff] {
            for &b in &[1u8, 2, 0x83, 0x1b, 0xfe] {
                for &c in &[1u8, 3, 0x55, 0xc1, 0xee] {
                    let a = Gf256(a);
                    let b = Gf256(b);
                    let c = Gf256(c);
                    let lhs = a.mul(b.add(c));
                    let rhs = a.mul(b).add(a.mul(c));
                    assert_eq!(lhs, rhs);
                }
            }
        }
    }

    #[test]
    fn every_nonzero_element_has_an_inverse() {
        for v in 1..=255u8 {
            let x = Gf256(v);
            let inv = x.inv();
            assert_eq!(x.mul(inv), Gf256::ONE, "{v:#x} · inv = 1");
            assert_eq!(inv.mul(x), Gf256::ONE);
        }
    }

    #[test]
    fn inverse_of_zero_is_zero_by_convention() {
        assert_eq!(Gf256::ZERO.inv(), Gf256::ZERO);
    }

    #[test]
    fn evaluate_polynomial_horner() {
        // p(x) = 1 + 2x + 3x^2 over GF(2^8): p(0)=1, p(1)=1^2^3=0, p(2)=1^4^0x0c=9.
        let coeffs = [Gf256(1), Gf256(2), Gf256(3)];
        assert_eq!(Gf256::evaluate_polynomial(&coeffs, Gf256(0)), Gf256(1));
        assert_eq!(Gf256::evaluate_polynomial(&coeffs, Gf256(1)), Gf256(0));
        assert_eq!(Gf256::evaluate_polynomial(&coeffs, Gf256(2)), Gf256(9));
    }

    #[test]
    fn polynomial_of_degree_zero_is_constant() {
        let coeffs = [Gf256(0x42)];
        for v in 0..=255u8 {
            assert_eq!(
                Gf256::evaluate_polynomial(&coeffs, Gf256(v)),
                Gf256(0x42),
                "constant polynomial at x={v}",
            );
        }
    }
}
