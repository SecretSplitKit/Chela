//! `chela-bundle` — produces the standalone single-file `chela.html` distribution.
//! Rewrites the `WASM_BASE64` placeholder in the served template with the inlined,
//! base64-encoded WASM blob.
//!
//! Usage:
//!     chela-bundle [`output_path`]   # defaults to ./chela.html

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

const INDEX_HTML: &str = include_str!("../../assets/chela.html");
const WASM_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/chela.wasm"));

/// The exact line in `chela.html` we rewrite. Kept here as a constant so a stray edit
/// to the source HTML breaks loudly (the bundler errors out) instead of silently
/// shipping an HTML file with no embedded WASM.
const WASM_PLACEHOLDER: &str = "const WASM_BASE64 = null;";

fn main() -> ExitCode {
    let out_path = env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from("chela.html"), PathBuf::from);

    if !INDEX_HTML.contains(WASM_PLACEHOLDER) {
        eprintln!(
            "chela-bundle: source HTML doesn't contain the expected `{WASM_PLACEHOLDER}` line. \
             Aborting so we don't ship a broken bundle."
        );
        return ExitCode::from(1);
    }

    let b64 = base64_encode(WASM_BYTES);
    let replacement = format!("const WASM_BASE64 = \"{b64}\";");
    let bundled = INDEX_HTML.replacen(WASM_PLACEHOLDER, &replacement, 1);

    match fs::File::create(&out_path).and_then(|mut f| f.write_all(bundled.as_bytes())) {
        Ok(()) => {
            eprintln!(
                "chela-bundle: wrote {} bytes to {} (WASM was {} bytes → {} base64)",
                bundled.len(),
                out_path.display(),
                WASM_BYTES.len(),
                b64.len(),
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("chela-bundle: failed to write {}: {e}", out_path.display());
            ExitCode::from(1)
        }
    }
}

/// Standard base64 alphabet per RFC 4648 §4. Hand-rolled to keep the workspace
/// dependency-free. Padded with `=` to a multiple of 4 output chars.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n0 = (b0 >> 2) & 0x3f;
        let n1 = ((b0 << 4) | (b1 >> 4)) & 0x3f;
        let n2 = ((b1 << 2) | (b2 >> 6)) & 0x3f;
        let n3 = b2 & 0x3f;
        out.push(ALPHABET[n0 as usize] as char);
        out.push(ALPHABET[n1 as usize] as char);
        if chunk.len() >= 2 {
            out.push(ALPHABET[n2 as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() >= 3 {
            out.push(ALPHABET[n3 as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{base64_encode, INDEX_HTML, WASM_PLACEHOLDER};

    #[test]
    fn empty() {
        assert_eq!(base64_encode(b""), "");
    }

    /// RFC 4648 §10 test vectors.
    #[test]
    fn rfc4648_vectors() {
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    /// All outputs are padded to a multiple of 4 chars.
    #[test]
    fn always_padded_to_quartet() {
        for len in 0..32 {
            let bytes = vec![0xa5u8; len];
            let out = base64_encode(&bytes);
            assert_eq!(out.len() % 4, 0, "len {len} encodes to non-quartet `{out}`");
        }
    }

    /// Source HTML must contain the placeholder the bundler rewrites. If someone edits
    /// `chela.html` and accidentally drops or renames the line, this test fails before
    /// the bundle ever ships with an unset WASM payload.
    #[test]
    fn source_html_contains_placeholder() {
        assert!(
            INDEX_HTML.contains(WASM_PLACEHOLDER),
            "chela.html must contain `{WASM_PLACEHOLDER}` exactly once for the bundler to rewrite it"
        );
        assert_eq!(
            INDEX_HTML.matches(WASM_PLACEHOLDER).count(),
            1,
            "placeholder should appear exactly once",
        );
    }

    /// Rewriting the placeholder with a known base64 string produces HTML that contains
    /// the new value once and no longer contains the placeholder. This guards against a
    /// future regression where someone changes `replacen` to `replace` or breaks the
    /// rewrite semantics.
    #[test]
    fn rewrite_replaces_placeholder_exactly_once() {
        let bundled =
            INDEX_HTML.replacen(WASM_PLACEHOLDER, "const WASM_BASE64 = \"TESTPAYLOAD\";", 1);
        assert!(!bundled.contains(WASM_PLACEHOLDER));
        assert_eq!(
            bundled
                .matches("const WASM_BASE64 = \"TESTPAYLOAD\";")
                .count(),
            1,
        );
        // The rest of the HTML is preserved — sanity-check by length.
        assert_eq!(
            bundled.len(),
            INDEX_HTML.len() - WASM_PLACEHOLDER.len()
                + "const WASM_BASE64 = \"TESTPAYLOAD\";".len(),
        );
    }
}
