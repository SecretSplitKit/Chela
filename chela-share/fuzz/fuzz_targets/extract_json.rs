//! Fuzz harness for the JSON import path (`chela_share::extract_shares_from_json`).
//!
//! Arbitrary bytes, lossy-decoded to a `&str`, must never panic, loop forever, or
//! over-allocate. The target is the hand-rolled JSON parser (depth limit, unicode
//! escapes, surrogate handling) and the single/bundle share decoder.
//!
//! Run with:  cargo +nightly fuzz run extract_json

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let json = String::from_utf8_lossy(data);
    let _ = chela_share::extract_shares_from_json(&json);
});
