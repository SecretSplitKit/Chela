//! Fuzz harness for the HTML import path (`chela_share::extract_shares_from_html`).
//!
//! Arbitrary bytes, lossy-decoded to a `&str`, must never panic, loop forever, or
//! over-allocate. The target is the bespoke `<script class="chela-share">` block
//! scanner and the attribute matcher.
//!
//! Run with:  cargo +nightly fuzz run extract_html

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let html = String::from_utf8_lossy(data);
    let _ = chela_share::extract_shares_from_html(&html);
});
