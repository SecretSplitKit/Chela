//! Cryptographic primitives for chela: SHA-256, constant-time comparison, OS RNG, and zeroization.

#![no_std]
#![deny(unsafe_code)]

pub mod crc;
pub mod ct;
pub mod rng;
pub mod sha256;
pub mod zeroize;
