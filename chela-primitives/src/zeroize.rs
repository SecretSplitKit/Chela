//! Volatile-write zeroization. Wipes secret bytes via `core::ptr::write_volatile`, which
//! the optimiser may not elide.

#![allow(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic;

/// Overwrite every byte in `slice` with zero using volatile writes. A `SeqCst` compiler
/// fence at the end prevents subsequent non-volatile reads from being reordered ahead.
pub fn volatile_set(slice: &mut [u8]) {
    for byte in slice.iter_mut() {
        // SAFETY: `byte` is a unique mutable reference to a single `u8`, so the raw
        // pointer derived from it is valid for writes for the duration of this call;
        // `0u8` is a valid bit-pattern for `u8`; no alignment requirements apply to a
        // byte; no aliasing concerns because we hold the unique `&mut`.
        unsafe {
            ptr::write_volatile(core::ptr::from_mut::<u8>(byte), 0);
        }
    }
    atomic::compiler_fence(atomic::Ordering::SeqCst);
}

/// Types that know how to wipe themselves.
pub trait Zeroize {
    fn zeroize(&mut self);
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        volatile_set(self);
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        volatile_set(self.as_mut_slice());
    }
}

impl<const N: usize> Zeroize for [u32; N] {
    fn zeroize(&mut self) {
        // SAFETY: `[u32; N]` has no padding and any byte pattern is a valid `[u8; 4*N]`,
        // so reinterpreting it as a byte slice for the duration of the write is sound.
        // The `&mut self` borrow guarantees unique access.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                self.as_mut_ptr().cast::<u8>(),
                core::mem::size_of_val(self),
            )
        };
        volatile_set(bytes);
    }
}

impl Zeroize for [u16] {
    fn zeroize(&mut self) {
        // SAFETY: `[u16]` has no padding; any byte pattern is valid for `[u8; 2*N]`.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                self.as_mut_ptr().cast::<u8>(),
                core::mem::size_of_val(self),
            )
        };
        volatile_set(bytes);
    }
}

impl<const N: usize> Zeroize for [u16; N] {
    fn zeroize(&mut self) {
        Zeroize::zeroize(self.as_mut_slice());
    }
}

impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        volatile_set(self.as_mut_slice());
    }
}

impl Zeroize for Vec<u16> {
    fn zeroize(&mut self) {
        Zeroize::zeroize(self.as_mut_slice());
    }
}

impl Zeroize for String {
    fn zeroize(&mut self) {
        // SAFETY: `volatile_set` writes 0x00 to every byte. An all-zero byte sequence
        // is valid UTF-8 (a run of NUL characters), so the String's UTF-8 invariant is
        // preserved across the write.
        let bytes = unsafe { self.as_mut_vec() };
        volatile_set(bytes.as_mut_slice());
    }
}

/// Wrapper that zeroizes its inner value when dropped.
pub struct Zeroizing<T: Zeroize> {
    value: T,
}

impl<T: Zeroize> Zeroizing<T> {
    pub const fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T: Zeroize> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: Zeroize> core::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

// Hide contents from `Debug` so a stray `println!("{:?}", …)` can't leak the secret.
impl<T: Zeroize> core::fmt::Debug for Zeroizing<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Zeroizing").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{volatile_set, Zeroize, Zeroizing};
    use core::cell::Cell;

    #[test]
    fn volatile_set_clears_a_byte_slice() {
        let mut buf = [0xaau8; 32];
        volatile_set(&mut buf);
        assert_eq!(buf, [0u8; 32]);
    }

    #[test]
    fn volatile_set_clears_an_empty_slice_without_panicking() {
        let mut buf: [u8; 0] = [];
        volatile_set(&mut buf);
    }

    #[test]
    fn zeroize_trait_for_byte_array() {
        let mut buf = [0xcc_u8; 64];
        Zeroize::zeroize(&mut buf);
        assert_eq!(buf, [0u8; 64]);
    }

    #[test]
    fn zeroize_trait_for_byte_slice() {
        let mut buf = [0x55_u8; 16];
        Zeroize::zeroize(buf.as_mut_slice());
        assert_eq!(buf, [0u8; 16]);
    }

    // Counter that records each `zeroize` call so we can assert `Drop` runs it exactly once.
    struct ZeroizeCounter<'a> {
        counter: &'a Cell<u32>,
    }

    impl Zeroize for ZeroizeCounter<'_> {
        fn zeroize(&mut self) {
            self.counter.set(self.counter.get() + 1);
        }
    }

    #[test]
    fn zeroizing_drop_calls_zeroize_exactly_once() {
        let counter = Cell::new(0u32);
        {
            let _wrapped = Zeroizing::new(ZeroizeCounter { counter: &counter });
            assert_eq!(counter.get(), 0, "no zeroize yet");
        }
        assert_eq!(counter.get(), 1, "zeroize ran exactly once on drop");
    }

    #[test]
    fn zeroizing_deref_lets_us_use_the_inner_value() {
        let mut z = Zeroizing::new([0u8; 8]);
        z[0] = 1;
        z[7] = 9;
        assert_eq!(z[0], 1);
        assert_eq!(z[7], 9);
    }
}
