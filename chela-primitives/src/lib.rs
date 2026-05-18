//! Cryptographic primitives for chela, implemented from scratch.
//!
//! `unsafe` is denied at the crate level; only `rng` and `zeroize` opt in, with every
//! usage documented by a `// SAFETY:` block.

#![no_std]
#![deny(unsafe_code)]

pub mod ct;
pub mod rng;
pub mod sha256;
pub mod zeroize;
