//! Deterministic replay corpus for the three parsers that ingest untrusted input:
//! the text card parser (`parse_share` / `parse_shares`), the HTML importer
//! (`extract_shares_from_html`), and the JSON importer (`extract_shares_from_json`).
//!
//! These are the same entry points the libFuzzer targets in `chela-share/fuzz`
//! drive. Generative fuzzing is a local / pre-release tool (it needs nightly and is
//! non-deterministic); this file is the fast, deterministic half that runs in
//! `cargo test` on every PR. The contract under test is the same one the fuzzers
//! assert: arbitrary input must never panic, loop forever, or over-allocate - it
//! must always come back as an `Ok`/`Err`. A reintroduced parser panic fails here.
//!
//! When a fuzz run turns up a new crashing input, add it (or a minimised form) to the
//! relevant list below so it can never regress.

use chela_share::{extract_shares_from_html, extract_shares_from_json, parse_share, parse_shares};

/// Lossy-decode like the fuzz harnesses do, so non-UTF-8 byte sequences exercise the
/// same `&str` code paths.
fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Adversarial byte inputs shared by the text parsers. Includes the historical crash
/// class (non-ASCII inside a `CHELA-...` header, fuzz crash 8c3bfb86) plus the input
/// shapes the `parse_shares` fuzzer explores.
const TEXT_CASES: &[&[u8]] = &[
    b"",
    b" ",
    b"\t\r\n   \n\n",
    b"CHELA-",
    b"CHELA-02C9-5-2-3-6",
    b"not-a-chela-header",
    // Non-ASCII in the header field: the byte-slice that 8c3bfb86 crashed on.
    "CHELA-\u{FFFD}W-1-2-3-1".as_bytes(),
    // Numeric fields that overflow every integer width.
    b"CHELA-FFFF-999999999999999999999999-2-3-1",
    b"CHELA-99999999-5-2-3-6",
    // Word lines: empty, single, and a long run of tokens.
    b"\n\nword word word\n\n",
    b"abandon abandon abandon abandon abandon abandon abandon abandon",
    // Blank-line-separated records (the `parse_shares` blob splitter).
    b"CHELA-02C9-5-2-3-6\nfoo bar baz\n\nCHELA-02C9-2-2-3-6\n\n\n",
    // Raw non-UTF-8 bytes and embedded NULs.
    &[0xff, 0xfe, 0x00, 0x41, 0x80, 0x0a, 0x42, 0xc0],
    // Unicode whitespace / separators that are not ASCII spaces.
    "CHELA-02C9-5-2-3-6\u{2028}\u{00a0}cactus\u{3000}float".as_bytes(),
];

#[test]
fn text_parsers_never_panic() {
    for &raw in TEXT_CASES {
        // Bulk parse: the whole blob, exactly as the fuzzer feeds `parse_shares`.
        let blob = lossy(raw);
        let _ = parse_shares(&blob);

        // Per-card parse: reproduce the fuzzer's split-offset header/words carve so the
        // `parse_share` path is hit with the same fragmentation it explores.
        if !raw.is_empty() {
            let split = (raw[0] as usize) % raw.len();
            let (hdr, words) = raw[1..].split_at(split.min(raw.len() - 1));
            let _ = parse_share(&lossy(hdr), &lossy(words));
        }
    }
}

#[test]
fn text_parser_rejects_non_ascii_header() {
    // The load-bearing `is_ascii()` guard: a 4-byte non-ASCII header field must be a
    // clean `Err`, not a slice-on-a-char-boundary panic.
    assert!(parse_share(
        "CHELA-\u{FFFD}W-1-2-3-1",
        "cactus float ghost shine baby talk"
    )
    .is_err());
}

/// Adversarial HTML for the `<script class="chela-share">` block scanner.
const HTML_CASES: &[&[u8]] = &[
    b"",
    b"<",
    b"<script",                         // unclosed tag - scanner must bail, not spin
    b"<scripting>nope</scripting>",     // must not match `<script`
    b"<script type=\"application/json\" class=\"chela-share\">",  // open, never closed
    // A chela block whose body is malformed JSON.
    b"<script type='application/json' class='chela-share'>{not json}</script>",
    // `</script>` injected inside the JSON payload (attacker-supplied, unescaped).
    b"<script class=\"chela-share\" type=\"application/json\">{\"type\":\"chela.share\",\"x\":\"</script> oops\"}</script>",
    // Attribute order swapped, mixed quotes, extra whitespace.
    b"<script   class = 'chela-share'   type= \"application/json\" >{}</script>",
    // Many empty script tags in a row.
    b"<script></script><script></script><script class=\"chela-share\" type=\"application/json\"></script>",
    // Pathological run of `<` with no real tag.
    b"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<scrip",
];

#[test]
fn html_importer_never_panics() {
    for &raw in HTML_CASES {
        let _ = extract_shares_from_html(&lossy(raw));
    }
}

/// Adversarial JSON for the hand-rolled parser and the share decoder.
const JSON_CASES: &[&[u8]] = &[
    b"",
    b"   ",
    b"{",
    b"[",
    b"\"unterminated",
    b"\"bad escape \\uZZZZ\"",
    b"\"lone surrogate \\uD800\"",
    b"\"surrogate pair \\uD83D\\uDE00\"",     // valid pair - must decode, not panic
    b"-",
    b"1e",
    // Number that overflows i64.
    b"999999999999999999999999999999",
    // Top-level array / scalar (no `type` field).
    b"[0,0,0,0,0,0,0,0]",
    b"42",
    b"true",
    // A chela.share object with wrong-typed / out-of-range advisory fields.
    b"{\"type\":\"chela.share\",\"words\":[],\"scheme\":\"bip39-wordlist\",\"card_number\":99999,\"recovery_set_id\":\"ZZZZ\"}",
    // A chela.shares bundle whose `shares` is not an array.
    b"{\"type\":\"chela.shares\",\"shares\":42}",
    // Trailing garbage after a complete value.
    b"{} trailing",
];

#[test]
fn json_importer_never_panics() {
    for &raw in JSON_CASES {
        let _ = extract_shares_from_json(&lossy(raw));
    }
}

#[test]
fn json_nesting_past_the_depth_limit_is_a_clean_error() {
    // 64 levels of array nesting is well past MAX_DEPTH (32): the parser must return a
    // depth error, not recurse into a stack overflow.
    let deep = format!("{}{}", "[".repeat(64), "]".repeat(64));
    assert!(extract_shares_from_json(&deep).is_err());
}

#[test]
fn json_wide_but_bounded_input_is_handled() {
    // A large flat array stays linear in the input size - no amplification, no panic.
    let wide = format!("[{}]", "0,".repeat(4000) + "0");
    let _ = extract_shares_from_json(&wide);
}
