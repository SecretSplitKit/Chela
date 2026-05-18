//! Fuzz harness for `chela_share::parse_share` and `parse_shares`.
//!
//! Goal: prove that arbitrary byte input — including malformed cards, truncated lines,
//! whitespace tortures, and unexpected unicode — never panics, never loops forever,
//! and never grows memory beyond what the input bounds suggest.
//!
//! Run with:  cargo +nightly fuzz run parse_shares
//!
//! The fuzzer drives both entry points the user can reach with raw text:
//!   - `parse_share(header, words)` — the per-card parse used by the recover wizard.
//!   - `parse_shares(input)` — the bulk-paste parser that splits on blank lines.
//!
//! Input shape: the first byte of `data` is used as a "split offset" (modulo input
//! length) to chop the rest into a header / words pair for `parse_share`. The full
//! data is also fed to `parse_shares` as one blob. UTF-8 lossy decode lets us throw
//! arbitrary bytes at code paths that nominally expect `&str`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // ---- per-card parse: pick a split point, lossy-decode both halves -------------
    let split = (data[0] as usize) % data.len();
    let (hdr_bytes, words_bytes) = data[1..].split_at(split.min(data.len() - 1));
    let hdr = String::from_utf8_lossy(hdr_bytes);
    let words = String::from_utf8_lossy(words_bytes);
    let _ = chela_share::parse_share(&hdr, &words);

    // ---- bulk parse: feed the whole blob -------------------------------------------
    let full = String::from_utf8_lossy(data);
    let _ = chela_share::parse_shares(&full);
});
