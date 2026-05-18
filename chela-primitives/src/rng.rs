//! OS-backed cryptographic randomness.
//!
//! Entry points per target: macOS `getentropy(3)`, Linux `getrandom(2)`, Windows
//! `BCryptGenRandom`, `wasm32-*` host-supplied import `chela.random_bytes`
//! `(ptr: i32, len: i32) -> i32` (see AUDITORS.md § 7).

#![allow(unsafe_code)]

/// Errors from the OS RNG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    SyscallFailed,
    Unsupported,
}

/// Fill `buf` with cryptographically-secure random bytes from the OS RNG.
#[cfg(target_os = "macos")]
pub fn fill_bytes(buf: &mut [u8]) -> Result<(), RngError> {
    macos::fill_bytes(buf)
}

/// Fill `buf` with cryptographically-secure random bytes from the OS RNG.
#[cfg(target_os = "linux")]
pub fn fill_bytes(buf: &mut [u8]) -> Result<(), RngError> {
    linux::fill_bytes(buf)
}

/// Fill `buf` with cryptographically-secure random bytes from the OS RNG.
#[cfg(target_os = "windows")]
pub fn fill_bytes(buf: &mut [u8]) -> Result<(), RngError> {
    windows::fill_bytes(buf)
}

/// Fill `buf` with cryptographically-secure random bytes from the OS RNG.
#[cfg(all(
    target_arch = "wasm32",
    not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
))]
pub fn fill_bytes(buf: &mut [u8]) -> Result<(), RngError> {
    wasm::fill_bytes(buf)
}

/// Fill `buf` with cryptographically-secure random bytes from the OS RNG.
#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_arch = "wasm32"
)))]
pub fn fill_bytes(buf: &mut [u8]) -> Result<(), RngError> {
    let _ = buf;
    Err(RngError::Unsupported)
}

#[cfg(target_os = "macos")]
mod macos {
    use super::RngError;
    use core::ffi::{c_int, c_void};

    // <sys/random.h>; linked from libSystem. `buflen` MUST be ≤ 256.
    unsafe extern "C" {
        fn getentropy(buf: *mut c_void, buflen: usize) -> c_int;
    }

    const MAX_PER_CALL: usize = 256;

    pub(super) fn fill_bytes(buf: &mut [u8]) -> Result<(), RngError> {
        for chunk in buf.chunks_mut(MAX_PER_CALL) {
            // SAFETY: `chunk` is a unique `&mut [u8]`, so its data pointer is valid for
            // writes for the full `chunk.len()` bytes. `chunk.len()` is in `1..=256` by
            // `chunks_mut(MAX_PER_CALL)`, satisfying the `getentropy` precondition. The
            // foreign function writes `chunk.len()` bytes into the buffer and does not
            // retain the pointer past the call. `u8` has no alignment requirements. The
            // exclusive reference precludes aliasing.
            let rc = unsafe { getentropy(chunk.as_mut_ptr().cast::<c_void>(), chunk.len()) };
            if rc != 0 {
                return Err(RngError::SyscallFailed);
            }
        }
        Ok(())
    }
}

// Linux — calls libc `getrandom` (glibc ≥ 2.25, musl ≥ 1.1.20).

#[cfg(target_os = "linux")]
mod linux {
    use super::RngError;
    use core::ffi::{c_int, c_void};

    unsafe extern "C" {
        fn getrandom(buf: *mut c_void, buflen: usize, flags: c_int) -> isize;
    }

    // Matches macOS's getentropy 256-byte cap; the kernel short-reads larger requests.
    const MAX_PER_CALL: usize = 256;

    pub(super) fn fill_bytes(buf: &mut [u8]) -> Result<(), RngError> {
        for chunk in buf.chunks_mut(MAX_PER_CALL) {
            let mut filled = 0;
            while filled < chunk.len() {
                // SAFETY: `chunk[filled..]` is a valid mutable byte slice; pointer is
                // valid for `chunk.len() - filled` bytes; `flags = 0` selects the default
                // (urandom pool, blocking until seeded at boot then non-blocking). No
                // aliasing concerns because we hold an exclusive `&mut`.
                let rc = unsafe {
                    getrandom(
                        chunk.as_mut_ptr().add(filled).cast::<c_void>(),
                        chunk.len() - filled,
                        0,
                    )
                };
                if rc < 0 {
                    // Any negative return (including EINTR) treated as fatal; EINTR is rare
                    // in non-interactive contexts.
                    return Err(RngError::SyscallFailed);
                }
                // rc ≥ 0 (checked above); `cast_unsigned` is the lint-clean isize→usize
                // for non-negative values. The kernel's getrandom contract guarantees
                // 0 ≤ rc ≤ buf.len, which is also bounded by chunk_len ≤ 256.
                filled += rc.cast_unsigned();
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::RngError;
    use core::ffi::c_void;

    type NtStatus = i32;
    const STATUS_SUCCESS: NtStatus = 0;

    // Lets BCryptGenRandom use the OS-preferred RNG with no algorithm handle.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut c_void,
            buffer: *mut u8,
            len: u32,
            flags: u32,
        ) -> NtStatus;
    }

    pub(super) fn fill_bytes(buf: &mut [u8]) -> Result<(), RngError> {
        // BCryptGenRandom length is u32; chunk for buffers larger than that.
        for chunk in buf.chunks_mut(u32::MAX as usize) {
            let len = u32::try_from(chunk.len()).map_err(|_| RngError::SyscallFailed)?;
            // SAFETY: `algorithm = NULL` is valid in combination with the
            // BCRYPT_USE_SYSTEM_PREFERRED_RNG flag. `chunk` is a unique mutable byte slice
            // of length `len`. The foreign function writes `len` bytes and does not
            // retain the pointer past the call.
            let rc = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    len,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if rc != STATUS_SUCCESS {
                return Err(RngError::SyscallFailed);
            }
        }
        Ok(())
    }
}

// WASM — host-provided import `chela.random_bytes(ptr, len) -> i32` (0 = success).

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::RngError;

    #[link(wasm_import_module = "chela")]
    unsafe extern "C" {
        fn random_bytes(ptr: *mut u8, len: usize) -> i32;
    }

    pub(super) fn fill_bytes(buf: &mut [u8]) -> Result<(), RngError> {
        if buf.is_empty() {
            return Ok(());
        }
        // SAFETY: `buf` is a unique mutable byte slice; pointer is valid for `buf.len()`
        // bytes. The imported host function is documented to fill the buffer and not
        // retain the pointer.
        let rc = unsafe { random_bytes(buf.as_mut_ptr(), buf.len()) };
        if rc != 0 {
            return Err(RngError::SyscallFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::fill_bytes;
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    use super::RngError;

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn fills_buffers_of_assorted_sizes() {
        let mut backing = [0u8; 1024];
        for &len in &[0_usize, 1, 16, 31, 32, 64, 255, 256, 257, 511, 512, 1024] {
            let buf = &mut backing[..len];
            buf.fill(0xaa);
            fill_bytes(buf).expect("OS RNG should not fail");
            if len >= 4 {
                assert!(buf.iter().any(|&b| b != 0), "len={len}: all-zero output");
                assert!(
                    buf.iter().any(|&b| b != 0xaa),
                    "len={len}: pattern unchanged \u{2014} did the call run?",
                );
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn two_consecutive_fills_differ() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_bytes(&mut a).unwrap();
        fill_bytes(&mut b).unwrap();
        assert_ne!(
            a, b,
            "two consecutive 32-byte fills produced identical output"
        );
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows",
        target_arch = "wasm32"
    )))]
    #[test]
    fn unsupported_target_returns_error() {
        let mut buf = [0u8; 16];
        assert_eq!(fill_bytes(&mut buf), Err(RngError::Unsupported));
    }
}
