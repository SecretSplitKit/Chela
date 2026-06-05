//! `chela-wasm` — WebAssembly bindings for the chela cryptographic core.
//!
//! Exposes a small C-ABI surface that an HTML / JavaScript UI calls. No `wasm-bindgen`,
//! no third-party crates; we hand-roll the FFI marshalling so the dependency surface
//! stays the same as the rest of the workspace.
//!
//! # Calling convention
//!
//! JS owns WASM memory and allocates input buffers via [`chela_alloc`], writes its
//! request bytes there, calls one of the action exports (e.g. [`chela_split`]) passing
//! the offset + length, then reads the response from the packed `(ptr, len)` return
//! value. JS is responsible for calling [`chela_dealloc`] on both the input buffer it
//! allocated and the output buffer the action returned.
//!
//! Return values pack a pointer + length into a single `u64`:
//!   - High 32 bits → `ptr` (offset into WASM linear memory)
//!   - Low 32 bits → `len`
//!
//! # Wire format
//!
//! Inputs are framed in a tiny tagged binary format (see `request` module). Outputs
//! are JSON for easy parsing on the JS side via `JSON.parse`.
//!
//! # RNG
//!
//! Randomness comes through `chela-primitives::rng`, which on `wasm32` calls a host
//! import declared as `#[link(wasm_import_module = "chela")] fn random_bytes(*mut u8,
//! usize) -> i32`. The host (JS) must wire this to `crypto.getRandomValues`. See the
//! example in `chela-primitives/src/rng.rs`.

#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unsafe_code)]
// FFI functions are intentionally `pub`-but-unreachable-from-Rust; they exist for the
// WASM ABI, not for in-crate consumption.
#![allow(clippy::missing_safety_doc, unreachable_pub)]

use std::string::String;
use std::vec::Vec;

mod json;
mod request;

use chela_engine::{
    recover_secret, split_secret, EngineError, OutputMode, RecoveredSecret, SplitInput,
};
use chela_share::{
    extract_shares_from_html, extract_shares_from_json, format_share, parse_share,
    render_paper_html, render_shares_json, BackupMeta, FormatError, ImportError,
};

/// Pack a `(ptr, len)` pair into a single `u64` for the FFI return value. High 32 bits
/// hold the pointer, low 32 bits hold the length.
#[allow(clippy::cast_possible_truncation)]
fn pack(ptr: *const u8, len: usize) -> u64 {
    // Truncating to u32 is correct: on wasm32 the pointer is already 32-bit, and we
    // reject `len > u32::MAX` everywhere upstream.
    let ptr_u32 = ptr as u32;
    let len_u32 = len as u32;
    (u64::from(ptr_u32) << 32) | u64::from(len_u32)
}

/// Leak a `Vec<u8>` to JS and return the packed `(ptr, len)`. JS is responsible for
/// calling [`chela_dealloc`] once it's done copying the bytes out.
fn leak_to_packed(mut v: Vec<u8>) -> u64 {
    v.shrink_to_fit();
    let ptr = v.as_ptr();
    let len = v.len();
    debug_assert_eq!(v.capacity(), v.len());
    core::mem::forget(v);
    pack(ptr, len)
}

/// Allocate `len` bytes of WASM memory and return a pointer (offset) to the start. The
/// caller must pair this with a [`chela_dealloc`] call once finished. A length of 0
/// returns a non-null but unspecified pointer; passing it to `chela_dealloc` is safe.
#[no_mangle]
pub extern "C" fn chela_alloc(len: u32) -> u32 {
    let v = vec![0u8; len as usize];
    let ptr = v.as_ptr() as u32;
    core::mem::forget(v);
    ptr
}

/// Free a buffer previously returned by [`chela_alloc`] or by one of the action exports.
/// `ptr` + `len` must exactly match the original allocation; passing a mismatched pair
/// is undefined behaviour.
///
/// # Safety
/// `ptr` must be a pointer returned by [`chela_alloc`] (or a packed-`(ptr,len)` return
/// from an action export); `len` must equal the original allocation length. After this
/// call, the buffer must not be touched again.
#[no_mangle]
pub unsafe extern "C" fn chela_dealloc(ptr: u32, len: u32) {
    if len == 0 {
        return;
    }
    // SAFETY: per the function contract, `ptr` originated from `Vec::with_capacity(len)`
    // via `chela_alloc` (or an equivalent `vec![0u8; len]`), and `len` matches that
    // allocation exactly. Reconstructing the Vec, volatile-wiping it, then letting it
    // Drop both clears any secret-bearing content (request inputs, response JSON) and
    // frees the buffer. The wipe is unconditional since this function can't tell secret
    // and non-secret payloads apart.
    let len = len as usize;
    // SAFETY (clippy lint allow): length == capacity here is intentional —
    // `chela_alloc` does `vec![0u8; len]`, which Vec promises produces
    // capacity == length. The action exports use `shrink_to_fit` before
    // forgetting, so their response buffers also satisfy length == capacity.
    #[allow(clippy::same_length_and_capacity)]
    // SAFETY: per the function contract above, `ptr` originated from `chela_alloc`
    // (or a `shrink_to_fit`'d response Vec) with exactly `len` bytes; reconstructing
    // and Dropping is sound.
    let mut v = unsafe { Vec::from_raw_parts(ptr as *mut u8, len, len) };
    chela_primitives::zeroize::volatile_set(&mut v);
    drop(v);
}

/// Split a secret into M-of-N shares. Input is the tagged binary request format
/// documented in `request::SplitRequest`; output is a JSON object:
///
/// ```json
/// { "ok": true, "shares": [{ "x": 1, "threshold": 3, "total": 5, "identifier": "9DA3",
///     "card_code": "CHELA-9DA3-1-3-5-25", "words": ["..."] }, ...] }
/// ```
///
/// or on error:
///
/// ```json
/// { "ok": false, "error": "human-readable explanation" }
/// ```
///
/// # Safety
/// `input_ptr` must be the start of a `chela_alloc`-allocated buffer of exactly
/// `input_len` bytes, populated with a well-formed `request::SplitRequest`.
#[no_mangle]
pub unsafe extern "C" fn chela_split(input_ptr: u32, input_len: u32) -> u64 {
    // SAFETY: caller's contract guarantees the pointer + length describe a valid buffer.
    let input = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let json = match do_split(input) {
        Ok(j) => j,
        Err(e) => error_response(&e),
    };
    leak_to_packed(json.into_bytes())
}

pub(crate) fn do_split(input: &[u8]) -> Result<String, String> {
    use std::fmt::Write as _;
    let req = request::SplitRequest::decode(input).map_err(|e| format!("bad request: {e}"))?;
    let (split_input, threshold, total) = match &req {
        request::SplitRequest::Bip39 {
            threshold,
            total,
            mnemonic,
            passphrase,
        } => (
            SplitInput::Bip39 {
                mnemonic,
                passphrase,
            },
            *threshold,
            *total,
        ),
        request::SplitRequest::Text {
            threshold,
            total,
            text,
        } => (SplitInput::Text { text }, *threshold, *total),
    };
    let shares = split_secret(&split_input, threshold, total, OutputMode::Bip39Wordlist)
        .map_err(|e| engine_error_to_string(&e))?;

    let mut out = String::from("{\"ok\":true,\"shares\":[");
    for (i, share) in shares.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        let _ = write!(
            out,
            "\"x\":{},\"threshold\":{},\"total\":{}",
            share.x, share.threshold, share.total
        );
        let id_hex = format!("{:02X}{:02X}", share.identifier[0], share.identifier[1]);
        let _ = write!(out, ",\"identifier\":{}", json::str(&id_hex));
        let card_text = format_share(share);
        let mut lines = card_text.lines();
        let header = lines.next().unwrap_or("");
        let words_line = lines.next().unwrap_or("");
        let _ = write!(out, ",\"card_code\":{}", json::str(header));
        out.push_str(",\"words\":[");
        for (j, w) in words_line.split_whitespace().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&json::str(w));
        }
        out.push(']');
        out.push('}');
    }
    out.push_str("]}");
    Ok(out)
}

/// Recover a secret from a set of shares. Input is the tagged binary request format
/// documented in `request::RecoverRequest`; output is a JSON object:
///
/// ```json
/// { "ok": true, "kind": "bip39", "mnemonic": "...", "passphrase": "..." }
/// ```
/// or
/// ```json
/// { "ok": true, "kind": "text", "text": "..." }
/// ```
/// or
/// ```json
/// { "ok": false, "error": "..." }
/// ```
///
/// # Safety
/// Same as [`chela_split`].
#[no_mangle]
pub unsafe extern "C" fn chela_recover(input_ptr: u32, input_len: u32) -> u64 {
    // SAFETY: caller's contract.
    let input = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let json = match do_recover(input) {
        Ok(j) => j,
        Err(e) => error_response(&e),
    };
    leak_to_packed(json.into_bytes())
}

pub(crate) fn do_recover(input: &[u8]) -> Result<String, String> {
    let req = request::RecoverRequest::decode(input).map_err(|e| format!("bad request: {e}"))?;
    let mut shares = Vec::with_capacity(req.shares.len());
    for (i, raw) in req.shares.iter().enumerate() {
        let share = parse_share(&raw.header, &raw.words)
            .map_err(|e| format!("share #{}: {}", i + 1, format_error_to_string(&e)))?;
        shares.push(share);
    }
    let recovered = recover_secret(&shares).map_err(|e| engine_error_to_string(&e))?;
    let json = match recovered {
        RecoveredSecret::Bip39 {
            mnemonic,
            passphrase,
        } => format!(
            "{{\"ok\":true,\"kind\":\"bip39\",\"mnemonic\":{},\"passphrase\":{}}}",
            json::str(&mnemonic),
            json::str(&passphrase),
        ),
        RecoveredSecret::Text { text } => format!(
            "{{\"ok\":true,\"kind\":\"text\",\"text\":{}}}",
            json::str(&text),
        ),
    };
    Ok(json)
}

/// Render a printable HTML page containing every share. Input is the tagged binary
/// request documented in `request::RenderPaperRequest`; output is the HTML as raw
/// bytes (not JSON-wrapped — the JS side gets a string it can drop into an iframe or
/// offer for download).
///
/// # Safety
/// Same as [`chela_split`].
#[no_mangle]
pub unsafe extern "C" fn chela_render_paper_html(input_ptr: u32, input_len: u32) -> u64 {
    // SAFETY: caller's contract.
    let input = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let bytes = match do_render_paper(input) {
        Ok(b) => b,
        Err(e) => error_response(&e).into_bytes(),
    };
    leak_to_packed(bytes)
}

pub(crate) fn do_render_paper(input: &[u8]) -> Result<Vec<u8>, String> {
    let req =
        request::RenderPaperRequest::decode(input).map_err(|e| format!("bad request: {e}"))?;

    let mut shares = Vec::with_capacity(req.shares.len());
    for (i, raw) in req.shares.iter().enumerate() {
        let share = parse_share(&raw.header, &raw.words)
            .map_err(|e| format!("share #{}: {}", i + 1, format_error_to_string(&e)))?;
        shares.push(share);
    }

    let meta = BackupMeta {
        backup_name: req.backup_name.as_deref(),
        description: req.description.as_deref(),
        shareholder_names: req.shareholder_names.as_deref(),
    };
    Ok(render_paper_html(&shares, &meta).into_bytes())
}

/// Render a `chela.shares.v1` JSON bundle covering every share in `req.shares`.
/// Mirrors what the CLI's `--json FILE` flag writes. Input is the same
/// `request::RenderPaperRequest` format as [`chela_render_paper_html`];
/// output is the bundle text as raw bytes (UTF-8), suitable for the JS side
/// to wrap in a Blob and offer for download.
///
/// # Safety
/// Same input contract as the other exports.
#[no_mangle]
pub unsafe extern "C" fn chela_render_shares_json(input_ptr: u32, input_len: u32) -> u64 {
    // SAFETY: caller's contract.
    let input = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let bytes = match do_render_shares_json(input) {
        Ok(b) => b,
        Err(e) => error_response(&e).into_bytes(),
    };
    leak_to_packed(bytes)
}

pub(crate) fn do_render_shares_json(input: &[u8]) -> Result<Vec<u8>, String> {
    let req =
        request::RenderPaperRequest::decode(input).map_err(|e| format!("bad request: {e}"))?;
    let mut shares = Vec::with_capacity(req.shares.len());
    for (i, raw) in req.shares.iter().enumerate() {
        let share = parse_share(&raw.header, &raw.words)
            .map_err(|e| format!("share #{}: {}", i + 1, format_error_to_string(&e)))?;
        shares.push(share);
    }
    let meta = BackupMeta {
        backup_name: req.backup_name.as_deref(),
        description: req.description.as_deref(),
        shareholder_names: req.shareholder_names.as_deref(),
    };
    Ok(render_shares_json(&shares, &meta).into_bytes())
}

/// Extract chela share data from an imported file. Input is the raw file bytes
/// (UTF-8); the function auto-detects format:
///
/// - **HTML** (chela paper-backup): contains `class="chela-share"` script blocks
/// - **JSON** (`chela.share.v1` single or `chela.shares.v1` bundle): first
///   non-whitespace byte is `{`
///
/// Output is a JSON object describing each share found:
///
/// ```json
/// {
///   "ok": true,
///   "shares": [
///     {"ok": true, "x": 1, "threshold": 3, "total": 5,
///      "identifier": "3058", "card_code": "CHELA-3058-1-3-5-40",
///      "words": ["security", "moment", ...]},
///     {"ok": false, "error": "embedded JSON did not parse: …"}
///   ]
/// }
/// ```
///
/// Each block reports its own success/error so the UI can show "imported 2 of
/// 3 blocks; one was corrupt: …". If no `<script class="chela-share">` block
/// is present at all, the top-level returns `{"ok": false, "error": "…"}`.
///
/// # Safety
/// Same input contract as the other exports.
#[no_mangle]
pub unsafe extern "C" fn chela_extract_shares(input_ptr: u32, input_len: u32) -> u64 {
    // SAFETY: caller's contract.
    let input = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let json = match do_extract_shares(input) {
        Ok(j) => j,
        Err(e) => error_response(&e),
    };
    leak_to_packed(json.into_bytes())
}

pub(crate) fn do_extract_shares(input: &[u8]) -> Result<String, String> {
    use std::fmt::Write as _;
    let text = core::str::from_utf8(input).map_err(|_| "input is not valid UTF-8".to_string())?;
    let trimmed = text.trim_start();
    // Route by detection: chela-HTML or HTML-shaped → HTML extractor (it owns
    // the NoChelaSharesFound error); JSON-shaped → JSON extractor; else flag
    // as unrecognised.
    let looks_html = text.contains(r#"class="chela-share""#)
        || text.contains("class='chela-share'")
        || trimmed.starts_with('<');
    let blocks = if looks_html {
        match extract_shares_from_html(text) {
            Ok(b) => b,
            Err(ImportError::NoChelaSharesFound) => {
                return Err("no chela share data found in this HTML file".to_string());
            }
            Err(e) => return Err(format!("{e}")),
        }
    } else if trimmed.starts_with('{') {
        match extract_shares_from_json(text) {
            Ok(b) => b,
            Err(e) => return Err(format!("{e}")),
        }
    } else {
        return Err(
            "file is not a chela paper-backup HTML or a chela.share/chela.shares JSON file"
                .to_string(),
        );
    };

    let mut out = String::from("{\"ok\":true,\"shares\":[");
    for (i, result) in blocks.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        match result {
            Ok(share) => {
                out.push_str("{\"ok\":true");
                let _ = write!(
                    out,
                    ",\"x\":{},\"threshold\":{},\"total\":{}",
                    share.x, share.threshold, share.total,
                );
                let id_hex = format!("{:02X}{:02X}", share.identifier[0], share.identifier[1]);
                let _ = write!(out, ",\"identifier\":{}", json::str(&id_hex));
                let card_text = format_share(share);
                let mut lines = card_text.lines();
                let header = lines.next().unwrap_or("");
                let words_line = lines.next().unwrap_or("");
                let _ = write!(out, ",\"card_code\":{}", json::str(header));
                out.push_str(",\"words\":[");
                for (j, w) in words_line.split_whitespace().enumerate() {
                    if j > 0 {
                        out.push(',');
                    }
                    out.push_str(&json::str(w));
                }
                out.push(']');
                out.push('}');
            }
            Err(e) => {
                let _ = write!(
                    out,
                    "{{\"ok\":false,\"error\":{}}}",
                    json::str(&format!("{e}"))
                );
            }
        }
    }
    out.push_str("]}");
    Ok(out)
}

/// Cheap real-time check: is the given word in the BIP-39 English wordlist? Returns 1
/// if yes, 0 if no (or on invalid UTF-8 / empty input). Used by the web UI to mark
/// per-word inputs valid/invalid as the user types, so typos surface immediately
/// instead of waiting for the whole share to be validated.
///
/// # Safety
/// Same input contract as the other exports: `input_ptr` + `input_len` must describe
/// a `chela_alloc`-allocated UTF-8 byte slice.
#[no_mangle]
pub unsafe extern "C" fn chela_word_in_list(input_ptr: u32, input_len: u32) -> u32 {
    // SAFETY: caller's contract guarantees the pointer + length describe a valid buffer.
    let bytes = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    u32::from(word_in_list(bytes))
}

/// Whether the trimmed UTF-8 content of `bytes` is a BIP-39 word. Used by the FFI
/// shim above and the test suite. Invalid UTF-8 or empty input → `false`.
pub(crate) fn word_in_list(bytes: &[u8]) -> bool {
    let Ok(s) = core::str::from_utf8(bytes) else {
        return false;
    };
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return false;
    }
    chela_bip39::word_to_index(trimmed).is_some()
}

fn error_response(msg: &str) -> String {
    format!("{{\"ok\":false,\"error\":{}}}", json::str(msg))
}

fn engine_error_to_string(e: &EngineError) -> String {
    match e {
        EngineError::InvalidInput(s) => format!("invalid input: {s}"),
        EngineError::Sss(s) => format!("share-split failure: {s:?}"),
        EngineError::Bip39(b) => format!("BIP-39 error: {b:?}"),
        EngineError::BundleTooLarge => "secret too large to fit in a share".to_string(),
        EngineError::BundleCorrupt => {
            "combined shares didn't recover a valid secret — check the cards are from the same set"
                .to_string()
        }
        EngineError::MismatchedShares => {
            "shares are from different splits and can't be combined".to_string()
        }
        EngineError::ShareCorrupt => {
            "one or more shares failed the per-card checksum — likely a typo".to_string()
        }
        EngineError::UnknownWord => "word not in the BIP-39 wordlist".to_string(),
        EngineError::InsufficientShares => "not enough shares to recover".to_string(),
        EngineError::Utf8 => "recovered secret was not valid UTF-8".to_string(),
    }
}

fn format_error_to_string(e: &FormatError) -> String {
    match e {
        FormatError::BadHeader => "header should look like CHELA-9DA3-1-3-5-34".to_string(),
        FormatError::BadIdentifier => "set tag must be four hex digits (e.g. 9DA3)".to_string(),
        FormatError::BadThresholdTotal => {
            "M and N must be small whole numbers and M can't exceed N".to_string()
        }
        FormatError::BadShareIndex => "share number must be a whole number >= 1".to_string(),
        FormatError::BadWordCount => "word count must be a whole number".to_string(),
        FormatError::UnknownWord => "word not in the BIP-39 wordlist".to_string(),
        FormatError::MissingWords => "share has no words on the second line".to_string(),
        FormatError::WordCountMismatch => {
            "number of words doesn't match the header's word count".to_string()
        }
    }
}

// The FFI exports themselves can't be unit-tested on a 64-bit native target — they cast
// pointers to `u32`, which truncates outside `wasm32`. Instead these tests exercise the
// inner `do_split` / `do_recover` / `do_render_paper` / `word_in_list` functions that
// take `&[u8]` / `&str` directly. The FFI shells are exercised end-to-end in the
// browser by the Playwright tests.

#[cfg(test)]
mod tests {
    use super::*;

    fn build_split_bip39(threshold: u8, total: u8, mnemonic: &str, passphrase: &str) -> Vec<u8> {
        let mut buf = vec![0x01, threshold, total];
        push_lp(&mut buf, mnemonic);
        push_lp(&mut buf, passphrase);
        buf
    }

    fn build_split_text(threshold: u8, total: u8, text: &str) -> Vec<u8> {
        let mut buf = vec![0x02, threshold, total];
        push_lp(&mut buf, text);
        buf
    }

    fn build_recover(shares: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = vec![0x03];
        buf.extend_from_slice(&u16::try_from(shares.len()).unwrap().to_le_bytes());
        for (h, w) in shares {
            push_lp(&mut buf, h);
            push_lp(&mut buf, w);
        }
        buf
    }

    fn push_lp(buf: &mut Vec<u8>, s: &str) {
        let len = u32::try_from(s.len()).unwrap();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s.as_bytes());
    }

    fn parse_split_cards(json: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut search_from = 0;
        while let Some(idx) = json[search_from..].find("\"card_code\":\"") {
            let abs = search_from + idx + "\"card_code\":\"".len();
            let end = json[abs..].find('"').expect("closing quote");
            let header = json[abs..abs + end].to_owned();
            let w_start = json[abs + end..]
                .find("\"words\":[")
                .expect("words array follows card_code");
            let w_open = abs + end + w_start + "\"words\":[".len();
            let w_close = json[w_open..].find(']').expect("words array close");
            let words_raw = &json[w_open..w_open + w_close];
            let words: Vec<String> = words_raw
                .split(',')
                .map(|s| s.trim().trim_matches('"').to_owned())
                .collect();
            out.push((header, words.join(" ")));
            search_from = w_open + w_close;
        }
        out
    }

    const ABANDON_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn word_in_list_known_word() {
        assert!(word_in_list(b"abandon"));
        assert!(word_in_list(b"  about \n"));
    }

    #[test]
    fn word_in_list_unknown_word() {
        assert!(!word_in_list(b"notaword"));
        assert!(!word_in_list(b""));
        assert!(!word_in_list(b"   "));
        assert!(!word_in_list(&[0xff, 0xfe]));
    }

    #[test]
    fn split_then_recover_bip39_round_trip() {
        let req = build_split_bip39(3, 5, ABANDON_MNEMONIC, "");
        let split_json = do_split(&req).expect("split ok");
        assert!(split_json.contains("\"ok\":true"));
        let cards = parse_split_cards(&split_json);
        assert_eq!(cards.len(), 5, "got 5 cards");

        // Recover from cards 1, 3, 5 — non-contiguous subset exercises Lagrange.
        let subset: Vec<(&str, &str)> = [&cards[0], &cards[2], &cards[4]]
            .iter()
            .map(|(h, w)| (h.as_str(), w.as_str()))
            .collect();
        let rec_req = build_recover(&subset);
        let rec_json = do_recover(&rec_req).expect("recover ok");

        assert!(rec_json.contains("\"ok\":true"));
        assert!(rec_json.contains("\"kind\":\"bip39\""));
        assert!(rec_json.contains(&format!("\"mnemonic\":\"{ABANDON_MNEMONIC}\"")));
        assert!(rec_json.contains("\"passphrase\":\"\""));
    }

    #[test]
    fn split_then_recover_text_round_trip() {
        let req = build_split_text(2, 3, "correct horse battery staple");
        let split_json = do_split(&req).expect("split ok");
        let cards = parse_split_cards(&split_json);
        assert_eq!(cards.len(), 3);

        let subset: Vec<(&str, &str)> = [&cards[1], &cards[2]]
            .iter()
            .map(|(h, w)| (h.as_str(), w.as_str()))
            .collect();
        let rec_req = build_recover(&subset);
        let rec_json = do_recover(&rec_req).expect("recover ok");

        assert!(rec_json.contains("\"kind\":\"text\""));
        assert!(rec_json.contains("\"text\":\"correct horse battery staple\""));
    }

    #[test]
    fn split_with_bad_tag_returns_error() {
        let bad = vec![0xffu8, 3, 5, 0, 0, 0, 0];
        let err = do_split(&bad).unwrap_err();
        assert!(err.contains("bad request"));
    }

    #[test]
    fn recover_with_insufficient_shares_errors() {
        let split_req = build_split_bip39(3, 5, ABANDON_MNEMONIC, "");
        let cards = parse_split_cards(&do_split(&split_req).unwrap());

        let subset: Vec<(&str, &str)> = [&cards[0], &cards[1]]
            .iter()
            .map(|(h, w)| (h.as_str(), w.as_str()))
            .collect();
        let rec_req = build_recover(&subset);
        let err = do_recover(&rec_req).unwrap_err();
        assert!(err.contains("not enough shares"), "got: {err}");
    }

    #[test]
    fn recover_with_mismatched_sets_errors() {
        // Two independent splits produce different (random) set identifiers; combining
        // one card from each must fail.
        let a = parse_split_cards(&do_split(&build_split_text(2, 3, "alpha")).unwrap());
        let b = parse_split_cards(&do_split(&build_split_text(2, 3, "beta")).unwrap());

        let mixed: Vec<(&str, &str)> = vec![(&a[0].0, &a[0].1), (&b[0].0, &b[0].1)];
        let rec_req = build_recover(&mixed);
        let err = do_recover(&rec_req).unwrap_err();
        assert!(err.contains("different splits"), "got: {err}");
    }

    #[test]
    fn extract_html_shares_round_trips_rendered_paper_doc() {
        // Split → render paper HTML → extract every embedded share.
        let split_req = build_split_bip39(3, 5, ABANDON_MNEMONIC, "test passphrase");
        let cards = parse_split_cards(&do_split(&split_req).unwrap());

        let mut buf = vec![0x04u8];
        buf.extend_from_slice(&u16::try_from(cards.len()).unwrap().to_le_bytes());
        for (h, w) in &cards {
            push_lp(&mut buf, h);
            push_lp(&mut buf, w);
        }
        buf.push(1);
        push_lp(&mut buf, "Round-trip test wallet");
        buf.push(0);
        buf.push(0);

        let html_bytes = do_render_paper(&buf).unwrap();
        let extracted = do_extract_shares(&html_bytes).expect("extract ok");

        // Top-level reports success and lists exactly 5 entries.
        assert!(extracted.contains("\"ok\":true"));
        let block_count = extracted.matches("\"x\":").count();
        assert_eq!(block_count, 5, "all 5 shares should be extracted");

        // Every extracted card_code appears in the original split output too.
        for (h, _) in &cards {
            assert!(
                extracted.contains(h),
                "extracted JSON missing card_code {h}:\n{extracted}",
            );
        }
    }

    #[test]
    fn extract_html_shares_returns_top_level_error_when_no_blocks() {
        let html = b"<!doctype html><html><body><p>no chela here</p></body></html>";
        let err = do_extract_shares(html).unwrap_err();
        assert!(err.contains("no chela share data"), "got: {err}");
    }

    #[test]
    fn extract_html_shares_reports_per_block_errors_alongside_successes() {
        // Build a doc with one valid block + one corrupt block.
        let split_req = build_split_text(2, 3, "mix");
        let cards = parse_split_cards(&do_split(&split_req).unwrap());
        let mut buf = vec![0x04u8];
        buf.extend_from_slice(&u16::try_from(cards.len()).unwrap().to_le_bytes());
        for (h, w) in &cards {
            push_lp(&mut buf, h);
            push_lp(&mut buf, w);
        }
        buf.push(0);
        buf.push(0);
        buf.push(0);
        let valid_html_bytes = do_render_paper(&buf).unwrap();
        let valid_html = String::from_utf8(valid_html_bytes).unwrap();
        let corrupt_block =
            r#"<script type="application/json" class="chela-share">{not valid}</script>"#;
        let mixed = format!("{valid_html}{corrupt_block}");

        let extracted = do_extract_shares(mixed.as_bytes()).unwrap();
        // Three valid + one corrupt = 4 entries in the shares array.
        assert!(extracted.contains("\"ok\":true"));
        let ok_entries = extracted.matches(r#""ok":true,"x""#).count();
        let err_entries = extracted.matches(r#""ok":false,"error""#).count();
        assert_eq!(ok_entries, 3, "three valid shares");
        assert_eq!(err_entries, 1, "one corrupt block reported");
    }

    #[test]
    fn extract_html_shares_rejects_invalid_utf8() {
        let bad = [0xff, 0xfe, 0xfd];
        let err = do_extract_shares(&bad).unwrap_err();
        assert!(err.contains("UTF-8"), "got: {err}");
    }

    #[test]
    fn render_shares_json_produces_chela_shares_v1_bundle() {
        let split_req = build_split_bip39(2, 3, ABANDON_MNEMONIC, "");
        let cards = parse_split_cards(&do_split(&split_req).unwrap());

        let mut buf = vec![0x04u8];
        buf.extend_from_slice(&u16::try_from(cards.len()).unwrap().to_le_bytes());
        for (h, w) in &cards {
            push_lp(&mut buf, h);
            push_lp(&mut buf, w);
        }
        buf.push(1);
        push_lp(&mut buf, "Test wallet");
        buf.push(0);
        buf.push(0);

        let bytes = do_render_shares_json(&buf).expect("render ok");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(r#""type":"chela.shares.v1""#));
        assert!(text.contains(r#""backup_name":"Test wallet""#));
        // The bundle round-trips through chela_extract_shares.
        let extracted = do_extract_shares(text.as_bytes()).expect("extract ok");
        let block_count = extracted.matches("\"x\":").count();
        assert_eq!(block_count, 3);
    }

    #[test]
    fn extract_shares_auto_detects_json_single_share() {
        // chela.share.v1 file (single object) → one extracted share.
        let split_req = build_split_bip39(2, 3, ABANDON_MNEMONIC, "");
        let cards = parse_split_cards(&do_split(&split_req).unwrap());
        let mut buf = vec![0x04u8];
        buf.extend_from_slice(&u16::try_from(cards.len()).unwrap().to_le_bytes());
        for (h, w) in &cards {
            push_lp(&mut buf, h);
            push_lp(&mut buf, w);
        }
        buf.push(0);
        buf.push(0);
        buf.push(0);
        let bundle_text = String::from_utf8(do_render_shares_json(&buf).unwrap()).unwrap();

        // Pull one share object out of the bundle to construct a single-share file.
        let start = bundle_text.find(r#"{"type":"chela.share.v1""#).unwrap();
        // Walk to its matching brace (depth counting).
        let mut depth = 0i32;
        let mut end = start;
        for (i, c) in bundle_text[start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let single = &bundle_text[start..end];

        let extracted = do_extract_shares(single.as_bytes()).expect("extract ok");
        assert!(extracted.contains("\"x\":1"));
        let block_count = extracted.matches("\"x\":").count();
        assert_eq!(block_count, 1);
    }

    #[test]
    fn extract_shares_rejects_unrecognised_file() {
        // Plain text that isn't HTML and doesn't start with '{'.
        let err = do_extract_shares(b"hello world").unwrap_err();
        assert!(err.contains("not a chela"), "got: {err}");
    }

    #[test]
    fn render_paper_html_produces_full_card() {
        let split_req = build_split_bip39(2, 3, ABANDON_MNEMONIC, "");
        let cards = parse_split_cards(&do_split(&split_req).unwrap());

        let mut buf = vec![0x04u8];
        buf.extend_from_slice(&u16::try_from(cards.len()).unwrap().to_le_bytes());
        for (h, w) in &cards {
            push_lp(&mut buf, h);
            push_lp(&mut buf, w);
        }
        buf.push(1);
        push_lp(&mut buf, "Test wallet");
        buf.push(0);
        buf.push(0);

        let html_bytes = do_render_paper(&buf).expect("render ok");
        let html = String::from_utf8(html_bytes).expect("utf-8 html");
        assert!(html.contains("<article"));
        assert!(html.contains("Test wallet"));
        assert!(html.contains("Card code"));
        assert!(html.contains("Recovery set"));
        assert!(html.contains("How to recover the secret"));
    }
}
