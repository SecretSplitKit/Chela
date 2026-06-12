//! Finite-field abstraction for chela's SSS engine.

#![no_std]
#![forbid(unsafe_code)]

pub mod gf256;
pub use gf256::Gf256;

/// Finite-field operations. `add`, `sub`, `mul`, and `inv` must be constant-time over
/// secret inputs to satisfy chela's threat model.
pub trait Field: Copy + Eq + Sized {
    const ZERO: Self;
    const ONE: Self;

    #[must_use]
    fn add(self, rhs: Self) -> Self;
    #[must_use]
    fn sub(self, rhs: Self) -> Self;
    #[must_use]
    fn mul(self, rhs: Self) -> Self;

    /// Multiplicative inverse. `inv(ZERO) = ZERO` by convention (branch-free).
    #[must_use]
    fn inv(self) -> Self;

    /// Evaluate `p(x) = coeffs[0] + coeffs[1]*x + …` at `x` by Horner's method.
    /// Constant-time in `coeffs.len()`.
    #[must_use]
    fn evaluate_polynomial(coeffs: &[Self], x: Self) -> Self {
        let mut acc = Self::ZERO;
        for &c in coeffs.iter().rev() {
            acc = acc.mul(x).add(c);
        }
        acc
    }
}
